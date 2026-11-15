#include <peelf/security_audit.hpp>

#include <peelf/demangle.hpp>
#include <peelf/endian_reader.hpp>
#include <peelf/sha256.hpp>

#include <algorithm>
#include <array>
#include <cctype>
#include <charconv>
#include <cstring>
#include <format>
#include <fstream>
#include <iostream>
#include <set>
#include <sstream>
#include <string>
#include <string_view>
#include <unordered_map>

#ifdef _WIN32
#include <process.h>
#else
#include <unistd.h>
#endif

namespace peelf {
namespace {

constexpr std::array<SecurityRuleDescriptor, 19> kRuleCatalog = {{
    {"PE1001", "EnableAddressSpaceLayoutRandomization", SecurityRuleDomain::PE, SecuritySeverity::Error,
     "PE binaries must enable DYNAMIC_BASE (and HIGH_ENTROPY_VA on 64-bit targets).",
     "Link with /DYNAMICBASE (and /HIGHENTROPYVA on 64-bit targets) and retain base relocations."},
    {"PE1002", "EnableDataExecutionPrevention", SecurityRuleDomain::PE, SecuritySeverity::Error,
     "PE binaries must opt in to hardware Data Execution Prevention (NX_COMPAT).",
     "Link with /NXCOMPAT so data pages such as the stack and heap are non-executable."},
    {"PE1003", "EnableControlFlowGuard", SecurityRuleDomain::PE, SecuritySeverity::Warning,
     "PE binaries should enable Control Flow Guard (GUARD_CF) with a valid LoadConfig table.",
     "Compile and link with /guard:cf to validate indirect call targets at runtime."},
    {"PE1004", "EnableSafeSEH", SecurityRuleDomain::PE, SecuritySeverity::Error,
     "32-bit x86 PE binaries must either register a SafeSEH handler table or set NO_SEH.",
     "Link x86 PE32 binaries with /SAFESEH or mark exception-free images with /SAFESEH:NO only if NO_SEH is set."},
    {"PE1005", "SignBinaryWithAuthenticode", SecurityRuleDomain::PE, SecuritySeverity::Note,
     "PE binaries distributed in production should carry an Authenticode signature (and optional FORCE_INTEGRITY).",
     "Sign release binaries with signtool.exe and verify CertificateTable integrity."},
    {"PE1006", "EnableCetShadowStack", SecurityRuleDomain::PE, SecuritySeverity::Note,
     "x86/x64 PE binaries should opt in to hardware CET Shadow Stack (IMAGE_DLLCHARACTERISTICS_EX_CET_COMPAT).",
     "Link with /CETCOMPAT to emit IMAGE_DEBUG_TYPE_EX_DLLCHARACTERISTICS with CET_COMPAT."},
    {"PE1007", "DoNotMarkSectionsWritableAndExecutable", SecurityRuleDomain::PE, SecuritySeverity::Error,
     "PE sections must not combine writable and executable permissions (W^X violation).",
     "Separate code (.text, RX) and writable data (.data, RW); remove RWX linker /SECTION overrides."},
    {"PE1008", "DoNotUseWritableSharedSections", SecurityRuleDomain::PE, SecuritySeverity::Error,
     "PE sections must not combine IMAGE_SCN_MEM_WRITE and IMAGE_SCN_MEM_SHARED.",
     "Remove shared writable sections (#pragma comment(linker, \"/SECTION:...,RWS\")); use explicit IPC with ACLs."},

    {"ELF2001", "EnablePositionIndependentExecutable", SecurityRuleDomain::ELF, SecuritySeverity::Error,
     "ELF executables must be built as Position-Independent Executables (ET_DYN PIE) for full ASLR.",
     "Compile with -fPIE and link executables with -pie."},
    {"ELF2002", "MarkStackNonExecutable", SecurityRuleDomain::ELF, SecuritySeverity::Error,
     "ELF binaries must include PT_GNU_STACK without PF_X so thread stacks are non-executable.",
     "Link with -Wl,-z,noexecstack and ensure assembly objects include .note.GNU-stack."},
    {"ELF2003", "EnableRelocationReadOnly", SecurityRuleDomain::ELF, SecuritySeverity::Warning,
     "ELF binaries should enable Full RELRO (PT_GNU_RELRO + immediate binding) to protect GOT entries.",
     "Link with -Wl,-z,relro,-z,now so the dynamic loader marks the entire GOT read-only before entry."},
    {"ELF2004", "EnableStackProtector", SecurityRuleDomain::ELF, SecuritySeverity::Warning,
     "ELF binaries with C/C++ stack buffers should enable stack-smashing canaries.",
     "Compile with -fstack-protector-strong or -fstack-protector-all."},
    {"ELF2005", "FortifySourceFunctions", SecurityRuleDomain::ELF, SecuritySeverity::Warning,
     "ELF binaries importing fortifiable libc routines should compile with _FORTIFY_SOURCE.",
     "Compile optimized builds with -O2 -D_FORTIFY_SOURCE=2 (or -D_FORTIFY_SOURCE=3)."},
    {"ELF2006", "DoNotUseWritableExecutableSegments", SecurityRuleDomain::ELF, SecuritySeverity::Error,
     "ELF PT_LOAD segments and sections must not be simultaneously writable and executable (W^X).",
     "Link with -Wl,-z,noexecstack and eliminate writable+executable linker scripts or text relocations (-fPIC)."},
    {"ELF2007", "DoNotUseInsecureRunpath", SecurityRuleDomain::ELF, SecuritySeverity::Error,
     "ELF DT_RPATH and DT_RUNPATH entries must not reference relative '.', empty, or world-writable directories.",
     "Remove relative or /tmp paths from -Wl,-rpath and prefer standard trusted library paths."},
    {"ELF2008", "EnableControlFlowEnforcement", SecurityRuleDomain::ELF, SecuritySeverity::Note,
     "x86/x64 and AArch64 ELF binaries should emit hardware control-flow property notes (CET IBT/SHSTK or BTI/PAC).",
     "Compile x86/x64 with -fcf-protection=full and AArch64 with -mbranch-protection=standard."},

    {"LIVE3001", "AvoidLiveReadWriteExecuteRegions", SecurityRuleDomain::LiveProcess, SecuritySeverity::Warning,
     "Running processes should avoid simultaneous read+write+execute (RWX) virtual memory mappings.",
     "Transition JIT code pages from RW to RX via mprotect/VirtualProtect rather than keeping RWX mappings."},
    {"LIVE3002", "InspectUnbackedExecutableMemory", SecurityRuleDomain::LiveProcess, SecuritySeverity::Warning,
     "Executable anonymous mappings not backed by an on-disk module warrant inspection for JIT or injected code.",
     "Verify whether anonymous executable pages belong to a known JIT runtime or represent unauthorized shellcode."},
    {"LIVE3003", "VerifyProcessRuntimeMitigations", SecurityRuleDomain::LiveProcess, SecuritySeverity::Warning,
     "Process-level runtime mitigations (ASLR, DEP, Seccomp/NoNewPrivs) should remain active.",
     "Enable OS ASLR/DEP policies and apply Seccomp + PR_SET_NO_NEW_PRIVS sandboxing where supported."},
}};

void tally_finding(SecurityAuditReport& report, SecurityFinding finding) {
    switch (finding.severity) {
        case SecuritySeverity::Pass:    ++report.pass_count; break;
        case SecuritySeverity::Note:    ++report.note_count; break;
        case SecuritySeverity::Warning: ++report.warning_count; break;
        case SecuritySeverity::Error:   ++report.error_count; break;
    }
    report.findings.push_back(std::move(finding));
}

[[nodiscard]] std::string lower_ascii(std::string_view s) {
    std::string out;
    out.reserve(s.size());
    for (char ch : s) {
        out.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(ch))));
    }
    return out;
}

[[nodiscard]] std::optional<std::uint64_t> locate_pe_optional_header_offset(
    std::span<const std::uint8_t> raw_bytes) noexcept {
    if (raw_bytes.size() < 0x40u || raw_bytes[0] != 'M' || raw_bytes[1] != 'Z') {
        return std::nullopt;
    }
    const std::uint32_t lfanew =
        static_cast<std::uint32_t>(raw_bytes[0x3Cu]) |
        (static_cast<std::uint32_t>(raw_bytes[0x3Du]) << 8u) |
        (static_cast<std::uint32_t>(raw_bytes[0x3Eu]) << 16u) |
        (static_cast<std::uint32_t>(raw_bytes[0x3Fu]) << 24u);
    if (static_cast<std::size_t>(lfanew) + 24u > raw_bytes.size()) {
        return std::nullopt;
    }
    if (raw_bytes[lfanew] != 'P' || raw_bytes[lfanew + 1u] != 'E') {
        return std::nullopt;
    }
    return static_cast<std::uint64_t>(lfanew) + 24u;
}

void evaluate_pe_rules(const IBinaryImage& image,
                       std::span<const std::uint8_t> raw_bytes,
                       SecurityAuditReport& report) {
    const PeHeader* pe = image.pe_header();
    if (pe == nullptr) {
        report.status = SubsystemStatus::unavailable("security_audit", "PE header unavailable");
        return;
    }

    const std::optional<std::uint64_t> opt_off = locate_pe_optional_header_offset(raw_bytes);
    const std::optional<std::uint64_t> dll_chars_off =
        opt_off.has_value() ? std::optional<std::uint64_t>(*opt_off + 0x46u) : std::nullopt;
    const std::uint64_t base_va = image.image_base();

    const std::uint16_t dll_ch = pe->dll_characteristics;
    const std::uint16_t file_ch = pe->characteristics;

    const bool dynamic_base = (dll_ch & 0x0040u) != 0u;
    const bool high_entropy_va = (dll_ch & 0x0020u) != 0u;
    const bool nx_compat = (dll_ch & 0x0100u) != 0u;
    const bool force_integrity = (dll_ch & 0x0080u) != 0u;
    const bool no_seh = (dll_ch & 0x0400u) != 0u;
    const bool guard_cf = (dll_ch & 0x4000u) != 0u;
    const bool relocs_stripped = (file_ch & 0x0001u) != 0u;
    const bool has_reloc_blocks = !image.pe_base_relocations().empty();

    // PE1001: ASLR (`DYNAMIC_BASE` + `HIGH_ENTROPY_VA` on 64-bit)
    {
        SecurityFinding f;
        f.rule_id = "PE1001";
        f.rule_name = "EnableAddressSpaceLayoutRandomization";
        f.domain = SecurityRuleDomain::PE;
        f.subject = "OptionalHeader.DllCharacteristics";
        f.virtual_address = base_va;
        f.file_offset = dll_chars_off;
        f.remediation =
            "Link with /DYNAMICBASE (and /HIGHENTROPYVA on 64-bit targets) and avoid /FIXED or stripping .reloc.";

        if (!dynamic_base || relocs_stripped) {
            f.severity = SecuritySeverity::Error;
            f.summary = !dynamic_base
                            ? "ASLR is disabled (IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE is not set)."
                            : "IMAGE_FILE_RELOCS_STRIPPED is set, preventing runtime base relocation.";
            f.evidence = std::format(
                "DllCharacteristics=0x{:04X} (DYNAMIC_BASE={}), Characteristics=0x{:04X} (RELOCS_STRIPPED={}), BaseRelocBlocks={}",
                dll_ch,
                dynamic_base ? 1 : 0,
                file_ch,
                relocs_stripped ? 1 : 0,
                image.pe_base_relocations().size());
        } else if (image.is_64bit() && !high_entropy_va) {
            f.severity = SecuritySeverity::Warning;
            f.summary = "DYNAMIC_BASE is enabled, but 64-bit HIGH_ENTROPY_VA (0x0020) is not set.";
            f.evidence = std::format(
                "DllCharacteristics=0x{:04X} (DYNAMIC_BASE=1, HIGH_ENTROPY_VA=0), ImageBase=0x{:X}, BaseRelocBlocks={}",
                dll_ch,
                base_va,
                image.pe_base_relocations().size());
        } else {
            f.severity = SecuritySeverity::Pass;
            f.summary = image.is_64bit()
                            ? "ASLR and 64-bit High-Entropy VA are enabled."
                            : "ASLR (DYNAMIC_BASE) is enabled.";
            f.evidence = std::format(
                "DllCharacteristics=0x{:04X} (DYNAMIC_BASE=1{}{}), BaseRelocBlocks={}",
                dll_ch,
                image.is_64bit() ? ", HIGH_ENTROPY_VA=1" : "",
                has_reloc_blocks ? ", .reloc present" : "",
                image.pe_base_relocations().size());
        }
        tally_finding(report, std::move(f));
    }

    // PE1002: DEP (`NX_COMPAT`)
    {
        SecurityFinding f;
        f.rule_id = "PE1002";
        f.rule_name = "EnableDataExecutionPrevention";
        f.domain = SecurityRuleDomain::PE;
        f.subject = "OptionalHeader.DllCharacteristics";
        f.virtual_address = base_va;
        f.file_offset = dll_chars_off;
        f.remediation = "Link with /NXCOMPAT so data pages (stack/heap) are non-executable.";
        f.evidence = std::format("DllCharacteristics=0x{:04X} (NX_COMPAT={})", dll_ch, nx_compat ? 1 : 0);
        if (nx_compat) {
            f.severity = SecuritySeverity::Pass;
            f.summary = "Hardware Data Execution Prevention (NX_COMPAT) is enabled.";
        } else {
            f.severity = SecuritySeverity::Error;
            f.summary = "NX_COMPAT (0x0100) is not set; process data pages may remain executable.";
        }
        tally_finding(report, std::move(f));
    }

    // PE1003: Control Flow Guard (`GUARD_CF` + `LoadConfig`)
    {
        const PeLoadConfigDirectory* lcfg = image.pe_load_config_directory();
        const bool lcfg_has_cfg =
            lcfg != nullptr &&
            (lcfg->guard_cf_check_function_pointer != 0u ||
             lcfg->guard_cf_function_table != 0u ||
             (lcfg->guard_flags & 0x00000100u) != 0u); // IMAGE_GUARD_CF_INSTRUMENTED

        SecurityFinding f;
        f.rule_id = "PE1003";
        f.rule_name = "EnableControlFlowGuard";
        f.domain = SecurityRuleDomain::PE;
        f.subject = lcfg != nullptr ? "LoadConfigDirectory" : "OptionalHeader.DllCharacteristics";
        f.virtual_address = (lcfg != nullptr && lcfg->rva != 0u) ? (base_va + lcfg->rva) : base_va;
        f.file_offset = (lcfg != nullptr && lcfg->file_offset != 0u) ? std::optional<std::uint64_t>(lcfg->file_offset)
                                                                     : dll_chars_off;
        f.remediation = "Compile and link with /guard:cf so indirect call targets are validated via LoadConfig.";

        if (guard_cf && lcfg_has_cfg) {
            f.severity = SecuritySeverity::Pass;
            f.summary = "Control Flow Guard (GUARD_CF) is enabled and backed by a valid LoadConfig table.";
            f.evidence = std::format(
                "GUARD_CF=1, LoadConfig@RVA=0x{:X}, GuardCFCheckFunctionPointer=0x{:X}, GuardCFFunctionCount={}, GuardFlags=0x{:08X}",
                lcfg->rva,
                lcfg->guard_cf_check_function_pointer,
                lcfg->guard_cf_function_count,
                lcfg->guard_flags);
        } else if (guard_cf && !lcfg_has_cfg) {
            f.severity = SecuritySeverity::Error;
            f.summary = "GUARD_CF is set in DllCharacteristics, but LoadConfig lacks CFG instrumentation pointers.";
            f.evidence = std::format(
                "DllCharacteristics=0x{:04X} (GUARD_CF=1), LoadConfigPresent={}",
                dll_ch,
                lcfg != nullptr ? "yes (missing GuardCFCheckFunctionPointer/GuardFlags)" : "no");
        } else {
            f.severity = SecuritySeverity::Warning;
            f.summary = "Control Flow Guard (GUARD_CF) is not enabled.";
            f.evidence = std::format(
                "DllCharacteristics=0x{:04X} (GUARD_CF=0), LoadConfigPresent={}",
                dll_ch,
                lcfg != nullptr ? "yes" : "no");
        }
        tally_finding(report, std::move(f));
    }

    // PE1004: SafeSEH / `NO_SEH` on x86 PE32
    {
        const PeLoadConfigDirectory* lcfg = image.pe_load_config_directory();
        SecurityFinding f;
        f.rule_id = "PE1004";
        f.rule_name = "EnableSafeSEH";
        f.domain = SecurityRuleDomain::PE;
        f.subject = "ExceptionHandling";
        f.virtual_address = base_va;
        f.file_offset = dll_chars_off;
        f.remediation = "Link 32-bit x86 PE binaries with /SAFESEH (or set IMAGE_DLLCHARACTERISTICS_NO_SEH if SEH is unused).";

        if (image.architecture() != Architecture::X86 || image.is_64bit()) {
            f.severity = SecuritySeverity::Pass;
            f.summary = "Target architecture uses table-based unwind metadata (.pdata) rather than 32-bit stack SEH.";
            f.evidence = std::format(
                "Architecture={}, RuntimeFunctionEntries={}, NO_SEH={}",
                to_string(image.architecture()),
                image.pe_runtime_functions().size(),
                no_seh ? 1 : 0);
        } else if (no_seh) {
            f.severity = SecuritySeverity::Pass;
            f.summary = "IMAGE_DLLCHARACTERISTICS_NO_SEH is set; structured exception handlers are disallowed.";
            f.evidence = std::format("DllCharacteristics=0x{:04X} (NO_SEH=1)", dll_ch);
        } else if (lcfg != nullptr && lcfg->se_handler_table != 0u && lcfg->se_handler_count > 0u) {
            f.severity = SecuritySeverity::Pass;
            f.summary = "x86 SafeSEH handler table is registered in LoadConfig.";
            f.virtual_address = lcfg->se_handler_table;
            f.file_offset = lcfg->file_offset;
            f.evidence = std::format(
                "SEHandlerTable=0x{:X}, SEHandlerCount={}",
                lcfg->se_handler_table,
                lcfg->se_handler_count);
        } else {
            f.severity = SecuritySeverity::Error;
            f.summary = "32-bit x86 PE allows SEH without a SafeSEH handler table or NO_SEH flag.";
            f.evidence = std::format(
                "Architecture=X86 (PE32), NO_SEH=0, LoadConfig.SEHandlerTable=0x{:X}, SEHandlerCount={}",
                lcfg != nullptr ? lcfg->se_handler_table : 0ull,
                lcfg != nullptr ? lcfg->se_handler_count : 0ull);
        }
        tally_finding(report, std::move(f));
    }

    // PE1005: Authenticode `CertificateTable` / `FORCE_INTEGRITY`
    {
        const auto& certs = image.pe_certificates();
        SecurityFinding f;
        f.rule_id = "PE1005";
        f.rule_name = "SignBinaryWithAuthenticode";
        f.domain = SecurityRuleDomain::PE;
        f.subject = "CertificateTable";
        f.remediation = "Sign distributable PE binaries with Authenticode (signtool.exe) and enable /INTEGRITYCHECK when required.";

        if (!certs.empty()) {
            f.severity = SecuritySeverity::Pass;
            f.file_offset = certs.front().file_offset;
            f.summary = std::format("Embedded Authenticode CertificateTable present ({} entry/entries{}).",
                                    certs.size(),
                                    force_integrity ? ", FORCE_INTEGRITY=1" : "");
            f.evidence = std::format(
                "Cert[0]@file+0x{:X} (len={} bytes, rev=0x{:04X}, type=0x{:04X}), FORCE_INTEGRITY={}",
                certs.front().file_offset,
                certs.front().length,
                certs.front().revision,
                certs.front().certificate_type,
                force_integrity ? 1 : 0);
        } else if (force_integrity) {
            f.severity = SecuritySeverity::Error;
            f.virtual_address = base_va;
            f.file_offset = dll_chars_off;
            f.summary = "FORCE_INTEGRITY (0x0080) is set, but no Authenticode CertificateTable is present.";
            f.evidence = std::format("DllCharacteristics=0x{:04X} (FORCE_INTEGRITY=1), Certificates=0", dll_ch);
        } else {
            f.severity = SecuritySeverity::Note;
            f.virtual_address = base_va;
            f.file_offset = dll_chars_off;
            f.summary = "Binary is unsigned (no Authenticode CertificateTable present).";
            f.evidence = std::format("Certificates=0, FORCE_INTEGRITY=0 (DllCharacteristics=0x{:04X})", dll_ch);
        }
        tally_finding(report, std::move(f));
    }

    // PE1006: CET Shadow Stack (`IMAGE_DEBUG_TYPE_EX_DLLCHARACTERISTICS` == 20, bit 0x0001)
    {
        SecurityFinding f;
        f.rule_id = "PE1006";
        f.rule_name = "EnableCetShadowStack";
        f.domain = SecurityRuleDomain::PE;
        f.subject = "DebugDirectory.ExDllCharacteristics";
        f.remediation = "Link x86/x64 binaries with /CETCOMPAT to emit IMAGE_DLLCHARACTERISTICS_EX_CET_COMPAT.";

        if (image.architecture() != Architecture::X86 && image.architecture() != Architecture::X86_64) {
            f.severity = SecuritySeverity::Pass;
            f.summary = "Intel/AMD CET Shadow Stack is not applicable to non-x86 target architecture.";
            f.evidence = std::format("Architecture={}", to_string(image.architecture()));
        } else {
            bool found_ex_dir = false;
            std::uint32_t ex_flags = 0u;
            std::optional<std::uint64_t> ex_off{};
            std::optional<std::uint64_t> ex_va{};

            for (const PeDebugDirectory& dbg : image.pe_debug_directories()) {
                if (dbg.type == 20u && dbg.size_of_data >= 4u) { // IMAGE_DEBUG_TYPE_EX_DLLCHARACTERISTICS
                    found_ex_dir = true;
                    if (dbg.address_of_raw_data != 0u) {
                        ex_va = base_va + dbg.address_of_raw_data;
                    }
                    std::size_t off = dbg.pointer_to_raw_data;
                    if (off == 0u && dbg.address_of_raw_data != 0u) {
                        if (auto resolved = image.virtual_address_to_file_offset(base_va + dbg.address_of_raw_data);
                            resolved.has_value()) {
                            off = static_cast<std::size_t>(*resolved);
                        }
                    }
                    if (off + 4u <= raw_bytes.size()) {
                        ex_off = off;
                        ex_flags = static_cast<std::uint32_t>(raw_bytes[off]) |
                                   (static_cast<std::uint32_t>(raw_bytes[off + 1u]) << 8u) |
                                   (static_cast<std::uint32_t>(raw_bytes[off + 2u]) << 16u) |
                                   (static_cast<std::uint32_t>(raw_bytes[off + 3u]) << 24u);
                    }
                    break;
                }
            }

            f.virtual_address = ex_va.value_or(base_va);
            f.file_offset = ex_off.has_value() ? ex_off : dll_chars_off;

            if (found_ex_dir && (ex_flags & 0x0001u) != 0u) {
                f.severity = SecuritySeverity::Pass;
                f.summary = "CET Shadow Stack compatibility (IMAGE_DLLCHARACTERISTICS_EX_CET_COMPAT) is enabled.";
                f.evidence = std::format("ExDllCharacteristics=0x{:08X} (CET_COMPAT=1)", ex_flags);
            } else {
                f.severity = SecuritySeverity::Note;
                f.summary = "CET Shadow Stack compatibility (/CETCOMPAT) is not enabled.";
                f.evidence = found_ex_dir
                                 ? std::format("ExDllCharacteristics=0x{:08X} (CET_COMPAT=0)", ex_flags)
                                 : "No IMAGE_DEBUG_TYPE_EX_DLLCHARACTERISTICS (type 20) debug entry present";
            }
        }
        tally_finding(report, std::move(f));
    }

    // PE1007: Writable + Executable (`RWX`) sections
    {
        std::vector<const Section*> rwx;
        for (const Section& sec : image.sections()) {
            const bool is_rwx = (sec.writable && sec.executable) ||
                                ((sec.raw_flags & 0xA0000000ull) == 0xA0000000ull);
            if (is_rwx) {
                rwx.push_back(&sec);
            }
        }

        SecurityFinding f;
        f.rule_id = "PE1007";
        f.rule_name = "DoNotMarkSectionsWritableAndExecutable";
        f.domain = SecurityRuleDomain::PE;
        f.remediation = "Split writable data and executable code into distinct sections (enforce W^X).";

        if (rwx.empty()) {
            f.severity = SecuritySeverity::Pass;
            f.subject = "Sections";
            f.virtual_address = base_va;
            f.summary = "All PE sections enforce W^X (zero writable+executable sections).";
            f.evidence = std::format("Inspected {} PE section(s); none have IMAGE_SCN_MEM_WRITE | IMAGE_SCN_MEM_EXECUTE.",
                                     image.sections().size());
        } else {
            f.severity = SecuritySeverity::Error;
            f.subject = rwx.front()->name;
            f.virtual_address = rwx.front()->virtual_address;
            f.file_offset = rwx.front()->file_offset;
            f.summary = std::format("Found {} writable+executable (RWX) PE section(s), starting with '{}'.",
                                    rwx.size(),
                                    rwx.front()->name);
            std::string ev;
            for (std::size_t i = 0; i < rwx.size(); ++i) {
                if (i > 0u) ev += "; ";
                ev += std::format("{}@0x{:X} (Characteristics=0x{:08X}, vsize=0x{:X})",
                                  rwx[i]->name,
                                  rwx[i]->virtual_address,
                                  rwx[i]->raw_flags,
                                  rwx[i]->virtual_size);
            }
            f.evidence = std::move(ev);
        }
        tally_finding(report, std::move(f));
    }

    // PE1008: Writable + Shared (`IMAGE_SCN_MEM_WRITE | IMAGE_SCN_MEM_SHARED`) sections
    {
        std::vector<const Section*> rws;
        for (const Section& sec : image.sections()) {
            // IMAGE_SCN_MEM_SHARED = 0x10000000, IMAGE_SCN_MEM_WRITE = 0x80000000
            if ((sec.raw_flags & 0x90000000ull) == 0x90000000ull) {
                rws.push_back(&sec);
            }
        }

        SecurityFinding f;
        f.rule_id = "PE1008";
        f.rule_name = "DoNotUseWritableSharedSections";
        f.domain = SecurityRuleDomain::PE;
        f.remediation =
            "Remove IMAGE_SCN_MEM_SHARED from writable sections; use explicit named shared memory with strict ACLs.";

        if (rws.empty()) {
            f.severity = SecuritySeverity::Pass;
            f.subject = "Sections";
            f.virtual_address = base_va;
            f.summary = "Zero writable shared PE sections detected.";
            f.evidence = std::format("Inspected {} PE section(s); none combine IMAGE_SCN_MEM_WRITE | IMAGE_SCN_MEM_SHARED.",
                                     image.sections().size());
        } else {
            f.severity = SecuritySeverity::Error;
            f.subject = rws.front()->name;
            f.virtual_address = rws.front()->virtual_address;
            f.file_offset = rws.front()->file_offset;
            f.summary = std::format("Found {} writable+shared PE section(s) ('{}'), allowing cross-process tampering.",
                                    rws.size(),
                                    rws.front()->name);
            std::string ev;
            for (std::size_t i = 0; i < rws.size(); ++i) {
                if (i > 0u) ev += "; ";
                ev += std::format("{}@0x{:X} (Characteristics=0x{:08X})",
                                  rws[i]->name,
                                  rws[i]->virtual_address,
                                  rws[i]->raw_flags);
            }
            f.evidence = std::move(ev);
        }
        tally_finding(report, std::move(f));
    }

    report.status = SubsystemStatus::available(
        "security_audit",
        std::format("Evaluated 8 PE security rules: {} error(s), {} warning(s), {} note(s), {} pass",
                    report.error_count,
                    report.warning_count,
                    report.note_count,
                    report.pass_count));
}

struct ElfGnuProps {
    bool found_note{false};
    bool x86_ibt{false};
    bool x86_shstk{false};
    bool aarch64_bti{false};
    bool aarch64_pac{false};
};

[[nodiscard]] ElfGnuProps inspect_elf_gnu_properties(const IBinaryImage& image) {
    ElfGnuProps props{};
    const TargetLayout layout = TargetLayout::from_image(image);
    const std::size_t align = layout.pointer_size();

    for (const ElfNote& note : image.elf_notes()) {
        if (note.type != 5u || !note.name.starts_with("GNU")) { // NT_GNU_PROPERTY_TYPE_0
            continue;
        }
        props.found_note = true;
        const EndianReader reader(note.descriptor, layout);
        std::size_t off = 0u;
        while (reader.can_read(off, 8u)) {
            const auto pr_type = reader.read_u32(off);
            const auto pr_datasz = reader.read_u32(off + 4u);
            if (!pr_type || !pr_datasz) break;
            const auto dsz = static_cast<std::size_t>(*pr_datasz);
            if (!reader.can_read(off + 8u, dsz)) break;
            if (dsz >= 4u) {
                if (const auto bits = reader.read_u32(off + 8u)) {
                    if (*pr_type == 0xC0000002u) { // GNU_PROPERTY_X86_FEATURE_1_AND
                        props.x86_ibt = props.x86_ibt || ((*bits & 0x01u) != 0u);
                        props.x86_shstk = props.x86_shstk || ((*bits & 0x02u) != 0u);
                    } else if (*pr_type == 0xC0000000u) { // GNU_PROPERTY_AARCH64_FEATURE_1_AND
                        props.aarch64_bti = props.aarch64_bti || ((*bits & 0x01u) != 0u);
                        props.aarch64_pac = props.aarch64_pac || ((*bits & 0x02u) != 0u);
                    }
                }
            }
            const std::size_t unaligned = 8u + dsz;
            const std::size_t rem = unaligned % align;
            const std::size_t step = (rem == 0u) ? unaligned : (unaligned + (align - rem));
            if (step == 0u || off > note.descriptor.size() - step) break;
            off += step;
        }
    }
    return props;
}

void evaluate_elf_rules(const IBinaryImage& image,
                        SecurityAuditReport& report) {
    const ElfHeader* eh = image.elf_header();
    if (eh == nullptr) {
        report.status = SubsystemStatus::unavailable("security_audit", "ELF header unavailable");
        return;
    }

    const auto& phdrs = image.elf_program_headers();
    const auto& dyns = image.elf_dynamic_entries();
    const std::uint64_t base_va = image.image_base();

    bool has_pt_interp = !image.elf_interpreter().empty();
    const ElfProgramHeader* gnu_stack_ph = nullptr;
    const ElfProgramHeader* gnu_relro_ph = nullptr;
    std::vector<const ElfProgramHeader*> rwx_phdrs;

    for (const ElfProgramHeader& ph : phdrs) {
        if (ph.type == 3u) {
            has_pt_interp = true;
        } else if (ph.type == 0x6474E551u) { // PT_GNU_STACK
            gnu_stack_ph = &ph;
        } else if (ph.type == 0x6474E552u) { // PT_GNU_RELRO
            gnu_relro_ph = &ph;
        } else if (ph.type == 1u && (ph.flags & 0x03u) == 0x03u) { // PT_LOAD with PF_W | PF_X
            rwx_phdrs.push_back(&ph);
        }
    }

    bool has_dt_bind_now = false;
    bool has_dt_textrel = false;
    std::optional<std::uint64_t> dt_flags;
    std::optional<std::uint64_t> dt_flags_1;
    std::vector<std::string> rpaths;
    std::vector<std::string> runpaths;

    for (const ElfDynamicEntry& dyn : dyns) {
        if (dyn.tag == 24u) { // DT_BIND_NOW
            has_dt_bind_now = true;
        } else if (dyn.tag == 22u) { // DT_TEXTREL
            has_dt_textrel = true;
        } else if (dyn.tag == 30u) { // DT_FLAGS
            dt_flags = dyn.value;
        } else if (dyn.tag == 0x6FFFFFFBull) { // DT_FLAGS_1
            dt_flags_1 = dyn.value;
        } else if (dyn.tag == 15u && !dyn.string_value.empty()) { // DT_RPATH
            rpaths.push_back(dyn.string_value);
        } else if (dyn.tag == 29u && !dyn.string_value.empty()) { // DT_RUNPATH
            runpaths.push_back(dyn.string_value);
        }
    }

    const bool df_pie = dt_flags_1.has_value() && ((*dt_flags_1 & 0x08000000ull) != 0u);
    const bool bind_now =
        has_dt_bind_now ||
        (dt_flags.has_value() && ((*dt_flags & 0x08ull) != 0u)) ||
        (dt_flags_1.has_value() && ((*dt_flags_1 & 0x01ull) != 0u));
    const bool textrel =
        has_dt_textrel || (dt_flags.has_value() && ((*dt_flags & 0x04ull) != 0u));

    // ELF2001: PIE (`ET_DYN` with `PT_INTERP`/`DF_1_PIE` vs non-PIE `ET_EXEC`)
    {
        SecurityFinding f;
        f.rule_id = "ELF2001";
        f.rule_name = "EnablePositionIndependentExecutable";
        f.domain = SecurityRuleDomain::ELF;
        f.subject = "ElfHeader.e_type";
        f.virtual_address = image.entry_point() != 0u ? image.entry_point() : base_va;
        f.file_offset = 0x10u;
        f.remediation = "Compile with -fPIE and link executables with -pie so the kernel can randomize the load base.";

        if (eh->type == 2u) { // ET_EXEC
            f.severity = SecuritySeverity::Error;
            f.summary = "ELF binary is a non-PIE position-dependent executable (ET_EXEC) at a fixed virtual address.";
            f.evidence = std::format("e_type=ET_EXEC (2), ImageBase=0x{:X}, Entry=0x{:X}",
                                     base_va,
                                     image.entry_point());
        } else if (eh->type == 3u) { // ET_DYN
            f.severity = SecuritySeverity::Pass;
            f.summary = (df_pie || has_pt_interp)
                            ? "ELF executable is a Position-Independent Executable (ET_DYN PIE)."
                            : "ELF image is position-independent (ET_DYN shared object / PIE).";
            f.evidence = std::format("e_type=ET_DYN (3), DF_1_PIE={}, PT_INTERP='{}'",
                                     df_pie ? 1 : 0,
                                     image.elf_interpreter());
        } else {
            f.severity = SecuritySeverity::Note;
            f.summary = "ELF image is not a final linked executable/DSO (PIE determined at final link).";
            f.evidence = std::format("e_type={}", eh->type);
        }
        tally_finding(report, std::move(f));
    }

    // ELF2002: Non-executable stack (`PT_GNU_STACK` without `PF_X`)
    {
        SecurityFinding f;
        f.rule_id = "ELF2002";
        f.rule_name = "MarkStackNonExecutable";
        f.domain = SecurityRuleDomain::ELF;
        f.subject = "PT_GNU_STACK";
        f.remediation = "Link with -Wl,-z,noexecstack and ensure handwritten assembly files include .section .note.GNU-stack,\"\",@progbits.";

        if (gnu_stack_ph != nullptr) {
            f.file_offset = eh->program_header_offset;
            const bool exec_stack = (gnu_stack_ph->flags & 0x01u) != 0u;
            if (exec_stack) {
                f.severity = SecuritySeverity::Error;
                f.summary = "PT_GNU_STACK has PF_X set (RWX executable thread stack).";
                f.evidence = std::format("PT_GNU_STACK p_flags=0x{:X} (PF_X=1)", gnu_stack_ph->flags);
            } else {
                f.severity = SecuritySeverity::Pass;
                f.summary = "PT_GNU_STACK marks thread stacks non-executable.";
                f.evidence = std::format("PT_GNU_STACK p_flags=0x{:X} (PF_X=0)", gnu_stack_ph->flags);
            }
        } else if (eh->type == 1u) { // ET_REL
            const ElfSectionHeader* note_stack = nullptr;
            for (const ElfSectionHeader& sh : image.elf_section_headers()) {
                if (sh.name == ".note.GNU-stack") {
                    note_stack = &sh;
                    break;
                }
            }
            if (note_stack != nullptr && (note_stack->flags & 0x04ull) == 0u) {
                f.severity = SecuritySeverity::Pass;
                f.summary = "Relocatable object includes non-executable .note.GNU-stack section.";
                f.evidence = std::format(".note.GNU-stack sh_flags=0x{:X}", note_stack->flags);
            } else {
                f.severity = SecuritySeverity::Warning;
                f.summary = "Relocatable object lacks a non-executable .note.GNU-stack marker.";
                f.evidence = note_stack != nullptr ? "SHF_EXECINSTR set on .note.GNU-stack" : "Missing .note.GNU-stack section";
            }
        } else {
            f.severity = SecuritySeverity::Warning;
            f.file_offset = eh->program_header_offset;
            f.summary = "PT_GNU_STACK program header is missing; some kernels default to an executable stack.";
            f.evidence = std::format("Inspected {} program header(s); PT_GNU_STACK (0x6474E551) absent",
                                     phdrs.size());
        }
        tally_finding(report, std::move(f));
    }

    // ELF2003: RELRO (Full `PT_GNU_RELRO` + `BIND_NOW` vs Partial vs None)
    {
        SecurityFinding f;
        f.rule_id = "ELF2003";
        f.rule_name = "EnableRelocationReadOnly";
        f.domain = SecurityRuleDomain::ELF;
        f.subject = "PT_GNU_RELRO / Dynamic";
        f.remediation = "Link with -Wl,-z,relro,-z,now to enable Full RELRO.";

        if (eh->type == 1u) {
            f.severity = SecuritySeverity::Note;
            f.summary = "RELRO applies to linked executables and shared libraries (ET_REL object skipped).";
            f.evidence = "e_type=ET_REL";
        } else if (gnu_relro_ph != nullptr && bind_now) {
            f.severity = SecuritySeverity::Pass;
            f.virtual_address = gnu_relro_ph->virtual_address;
            f.file_offset = gnu_relro_ph->offset;
            f.summary = "Full RELRO is enabled (PT_GNU_RELRO + immediate symbol binding).";
            f.evidence = std::format(
                "PT_GNU_RELRO@0x{:X} (memsz=0x{:X}), BIND_NOW=1 (DT_BIND_NOW={}, DT_FLAGS=0x{:X}, DT_FLAGS_1=0x{:X})",
                gnu_relro_ph->virtual_address,
                gnu_relro_ph->memory_size,
                has_dt_bind_now ? 1 : 0,
                dt_flags.value_or(0u),
                dt_flags_1.value_or(0u));
        } else if (gnu_relro_ph != nullptr) {
            f.severity = SecuritySeverity::Warning;
            f.virtual_address = gnu_relro_ph->virtual_address;
            f.file_offset = gnu_relro_ph->offset;
            f.summary = "Only Partial RELRO is enabled; .got.plt remains writable for lazy PLT binding.";
            f.evidence = std::format(
                "PT_GNU_RELRO@0x{:X} (memsz=0x{:X}), BIND_NOW=0 (add -Wl,-z,now for Full RELRO)",
                gnu_relro_ph->virtual_address,
                gnu_relro_ph->memory_size);
        } else {
            f.severity = SecuritySeverity::Error;
            f.virtual_address = base_va;
            f.summary = "RELRO is disabled (missing PT_GNU_RELRO); Global Offset Table remains writable.";
            f.evidence = std::format("PT_GNU_RELRO=absent, BIND_NOW={}", bind_now ? 1 : 0);
        }
        tally_finding(report, std::move(f));
    }

    // Collect normalized symbol/import names once for ELF2004 & ELF2005
    auto strip_sym_version = [](std::string_view nm) noexcept -> std::string_view {
        const std::size_t at = nm.find('@');
        return at == std::string_view::npos ? nm : nm.substr(0u, at);
    };

    std::string canary_match;
    std::optional<std::uint64_t> canary_va{};
    std::vector<std::string> chk_symbols;
    std::vector<std::string> unfortified_libc;

    static constexpr std::array<std::string_view, 16> kFortifiableLibc = {
        "memcpy", "memmove", "memset", "strcpy", "strncpy", "strcat", "strncat",
        "sprintf", "snprintf", "vsprintf", "vsnprintf", "gets", "fgets",
        "printf", "fprintf", "vprintf"};

    auto inspect_symbol_name = [&](std::string_view raw, std::uint64_t va) {
        const std::string_view base_nm = strip_sym_version(raw);
        if (base_nm.empty()) return;
        if (base_nm == "__stack_chk_fail" || base_nm == "__stack_chk_fail_local" ||
            base_nm == "__stack_chk_guard" || base_nm == "__intel_security_cookie") {
            if (canary_match.empty()) {
                canary_match = std::string(base_nm);
                if (va != 0u) canary_va = va;
            }
        }
        if (base_nm.starts_with("__") && base_nm.ends_with("_chk")) {
            if (std::ranges::find(chk_symbols, base_nm) == chk_symbols.end()) {
                chk_symbols.emplace_back(base_nm);
            }
        }
        for (std::string_view fn : kFortifiableLibc) {
            if (base_nm == fn) {
                if (std::ranges::find(unfortified_libc, base_nm) == unfortified_libc.end()) {
                    unfortified_libc.emplace_back(base_nm);
                }
                break;
            }
        }
    };

    for (const ImportEntry& imp : image.imports()) {
        inspect_symbol_name(imp.name, imp.address);
    }
    for (const Symbol& sym : image.symbols()) {
        inspect_symbol_name(sym.name, sym.virtual_address);
    }

    // ELF2004: Stack protector canary (`__stack_chk_fail` / `__stack_chk_guard`)
    {
        SecurityFinding f;
        f.rule_id = "ELF2004";
        f.rule_name = "EnableStackProtector";
        f.domain = SecurityRuleDomain::ELF;
        f.subject = "Symbols / Imports";
        f.virtual_address = canary_va;
        f.remediation = "Compile C/C++ translation units with -fstack-protector-strong.";

        if (!canary_match.empty()) {
            f.severity = SecuritySeverity::Pass;
            f.summary = "Stack-smashing protector canary symbol detected.";
            f.evidence = std::format("Matched stack-protector symbol '{}'", canary_match);
        } else {
            f.severity = SecuritySeverity::Warning;
            f.summary = "No stack-protector canary symbols (__stack_chk_fail / __stack_chk_guard) detected.";
            f.evidence = std::format("Scanned {} import(s) and {} symbol(s); no __stack_chk_* symbol present",
                                     image.imports().size(),
                                     image.symbols().size());
        }
        tally_finding(report, std::move(f));
    }

    // ELF2005: `_FORTIFY_SOURCE` (`*_chk` symbols)
    {
        SecurityFinding f;
        f.rule_id = "ELF2005";
        f.rule_name = "FortifySourceFunctions";
        f.domain = SecurityRuleDomain::ELF;
        f.subject = "Symbols / Imports";
        f.remediation = "Compile optimized builds with -O2 -D_FORTIFY_SOURCE=2 (or -D_FORTIFY_SOURCE=3).";

        if (!chk_symbols.empty()) {
            f.severity = SecuritySeverity::Pass;
            f.summary = std::format("_FORTIFY_SOURCE hardened libc wrapper(s) detected ({} *_chk symbol(s)).",
                                    chk_symbols.size());
            std::string ev = "Fortified symbols: ";
            for (std::size_t i = 0; i < std::min<std::size_t>(chk_symbols.size(), 5u); ++i) {
                if (i > 0u) ev += ", ";
                ev += chk_symbols[i];
            }
            f.evidence = std::move(ev);
        } else if (!unfortified_libc.empty()) {
            f.severity = SecuritySeverity::Warning;
            f.summary = "Binary imports fortifiable libc functions without any *_chk _FORTIFY_SOURCE wrappers.";
            std::string ev = "Unfortified imports: ";
            for (std::size_t i = 0; i < std::min<std::size_t>(unfortified_libc.size(), 6u); ++i) {
                if (i > 0u) ev += ", ";
                ev += unfortified_libc[i];
            }
            f.evidence = std::move(ev);
        } else {
            f.severity = SecuritySeverity::Note;
            f.summary = "No fortifiable libc imports or *_chk wrappers observed in symbol tables.";
            f.evidence = "No standard libc buffer/format calls imported (e.g. freestanding, stripped static, or non-C runtime).";
        }
        tally_finding(report, std::move(f));
    }

    // ELF2006: `RWX` `PT_LOAD` segments or `SHF_WRITE | SHF_EXECINSTR` sections
    {
        std::vector<const Section*> rwx_secs;
        for (const Section& sec : image.sections()) {
            if (sec.writable && sec.executable) {
                rwx_secs.push_back(&sec);
            }
        }

        SecurityFinding f;
        f.rule_id = "ELF2006";
        f.rule_name = "DoNotUseWritableExecutableSegments";
        f.domain = SecurityRuleDomain::ELF;
        f.remediation = "Eliminate writable+executable PT_LOAD segments, SHF_WRITE|SHF_EXECINSTR sections, and DT_TEXTREL.";

        if (!rwx_phdrs.empty() || !rwx_secs.empty()) {
            f.severity = SecuritySeverity::Error;
            if (!rwx_secs.empty()) {
                f.subject = rwx_secs.front()->name;
                f.virtual_address = rwx_secs.front()->virtual_address;
                f.file_offset = rwx_secs.front()->file_offset;
            } else {
                f.subject = "PT_LOAD";
                f.virtual_address = rwx_phdrs.front()->virtual_address;
                f.file_offset = rwx_phdrs.front()->offset;
            }
            f.summary = std::format(
                "W^X violation: {} RWX PT_LOAD segment(s) and {} writable+executable section(s).",
                rwx_phdrs.size(),
                rwx_secs.size());
            std::string ev = std::format("RWX_PT_LOAD={}, RWX_Sections={}", rwx_phdrs.size(), rwx_secs.size());
            for (const Section* s : rwx_secs) {
                ev += std::format("; {}@0x{:X} (flags=0x{:X})", s->name, s->virtual_address, s->raw_flags);
            }
            for (const ElfProgramHeader* p : rwx_phdrs) {
                ev += std::format("; PT_LOAD@0x{:X} (p_flags=0x{:X})", p->virtual_address, p->flags);
            }
            f.evidence = std::move(ev);
        } else if (textrel) {
            f.severity = SecuritySeverity::Warning;
            f.subject = "DT_TEXTREL";
            f.virtual_address = base_va;
            f.summary = "DT_TEXTREL / DF_TEXTREL is set; dynamic loader must temporarily map code pages writable.";
            f.evidence = std::format("DT_TEXTREL={}, DT_FLAGS=0x{:X}", has_dt_textrel ? 1 : 0, dt_flags.value_or(0u));
        } else {
            f.severity = SecuritySeverity::Pass;
            f.subject = "Segments & Sections";
            f.virtual_address = base_va;
            f.summary = "All ELF PT_LOAD segments and sections strictly enforce W^X.";
            f.evidence = std::format("Inspected {} segment(s) and {} section(s); zero RWX mappings or textrels.",
                                     phdrs.size(),
                                     image.sections().size());
        }
        tally_finding(report, std::move(f));
    }

    // ELF2007: Insecure `DT_RPATH` / relative `.` / empty / `/tmp` runpath entries
    {
        SecurityFinding f;
        f.rule_id = "ELF2007";
        f.rule_name = "DoNotUseInsecureRunpath";
        f.domain = SecurityRuleDomain::ELF;
        f.subject = "Dynamic RPATH/RUNPATH";
        f.remediation =
            "Avoid empty ':', '.', relative, or world-writable (/tmp) paths in -Wl,-rpath; prefer DT_RUNPATH with root-owned absolute paths.";

        bool has_severe_issue = false;
        bool has_warning_issue = !rpaths.empty(); // DT_RPATH is deprecated & overrides LD_LIBRARY_PATH
        std::vector<std::string> problems;

        auto inspect_path_list = [&](std::string_view tag_name, const std::vector<std::string>& lists) {
            for (const std::string& raw : lists) {
                std::size_t start = 0u;
                while (true) {
                    const std::size_t colon = raw.find(':', start);
                    const std::string_view elem =
                        colon == std::string::npos
                            ? std::string_view(raw).substr(start)
                            : std::string_view(raw).substr(start, colon - start);

                    if (elem.empty() || elem == ".") {
                        has_severe_issue = true;
                        problems.push_back(std::format("{} contains current-directory token '{}'",
                                                       tag_name,
                                                       elem.empty() ? "<empty>" : "."));
                    } else if (elem == "/tmp" || elem.starts_with("/tmp/") ||
                               elem == "/var/tmp" || elem.starts_with("/var/tmp/")) {
                        has_severe_issue = true;
                        problems.push_back(std::format("{} references world-writable directory '{}'", tag_name, elem));
                    } else if (elem.starts_with("$ORIGIN") || elem.starts_with("${ORIGIN}")) {
                        has_warning_issue = true;
                        problems.push_back(std::format("{} uses $ORIGIN-relative path '{}' (verify install directory ACLs)",
                                                       tag_name,
                                                       elem));
                    } else if (!elem.starts_with('/')) {
                        has_severe_issue = true;
                        problems.push_back(std::format("{} contains relative search path '{}'", tag_name, elem));
                    }

                    if (colon == std::string::npos) break;
                    start = colon + 1u;
                }
            }
        };

        inspect_path_list("DT_RPATH", rpaths);
        inspect_path_list("DT_RUNPATH", runpaths);

        if (has_severe_issue) {
            f.severity = SecuritySeverity::Error;
            f.summary = "ELF dynamic search path contains insecure relative, empty, or world-writable directory entries.";
        } else if (has_warning_issue) {
            f.severity = SecuritySeverity::Warning;
            f.summary = !rpaths.empty()
                            ? "ELF uses deprecated DT_RPATH or $ORIGIN-relative search path requiring install-directory review."
                            : "ELF DT_RUNPATH uses $ORIGIN-relative search path; verify binary directory permissions.";
        } else {
            f.severity = SecuritySeverity::Pass;
            f.summary = "No insecure DT_RPATH or DT_RUNPATH entries detected.";
        }

        if (rpaths.empty() && runpaths.empty()) {
            f.evidence = "DT_RPATH=none, DT_RUNPATH=none";
        } else {
            std::string ev;
            if (!rpaths.empty()) ev += std::format("DT_RPATH='{}'", rpaths.front());
            if (!runpaths.empty()) {
                if (!ev.empty()) ev += ", ";
                ev += std::format("DT_RUNPATH='{}'", runpaths.front());
            }
            for (const std::string& p : problems) {
                ev += "; " + p;
            }
            f.evidence = std::move(ev);
        }
        tally_finding(report, std::move(f));
    }

    // ELF2008: Intel CET IBT/SHSTK `.note.gnu.property` / AArch64 BTI/PAC notes
    {
        const ElfGnuProps props = inspect_elf_gnu_properties(image);
        SecurityFinding f;
        f.rule_id = "ELF2008";
        f.rule_name = "EnableControlFlowEnforcement";
        f.domain = SecurityRuleDomain::ELF;
        f.subject = ".note.gnu.property";
        f.remediation =
            "Compile x86/x64 with -fcf-protection=full (IBT+SHSTK) or AArch64 with -mbranch-protection=standard (BTI+PAC).";

        const Architecture arch = image.architecture();
        if (arch == Architecture::X86 || arch == Architecture::X86_64) {
            if (props.x86_ibt && props.x86_shstk) {
                f.severity = SecuritySeverity::Pass;
                f.summary = "Intel CET Indirect Branch Tracking (IBT) and Shadow Stack (SHSTK) are both enabled.";
            } else if (props.x86_ibt || props.x86_shstk) {
                f.severity = SecuritySeverity::Note;
                f.summary = "Partial Intel CET property flags present in .note.gnu.property.";
            } else {
                f.severity = SecuritySeverity::Note;
                f.summary = "Intel CET property note (IBT/SHSTK) is not present.";
            }
            f.evidence = std::format("NT_GNU_PROPERTY_TYPE_0={}, X86_IBT={}, X86_SHSTK={}",
                                     props.found_note ? "present" : "absent",
                                     props.x86_ibt ? 1 : 0,
                                     props.x86_shstk ? 1 : 0);
        } else if (arch == Architecture::ARM64) {
            if (props.aarch64_bti && props.aarch64_pac) {
                f.severity = SecuritySeverity::Pass;
                f.summary = "AArch64 Branch Target Identification (BTI) and Pointer Authentication (PAC) are enabled.";
            } else if (props.aarch64_bti || props.aarch64_pac) {
                f.severity = SecuritySeverity::Note;
                f.summary = "Partial AArch64 branch protection flags present in .note.gnu.property.";
            } else {
                f.severity = SecuritySeverity::Note;
                f.summary = "AArch64 BTI/PAC property note is not present.";
            }
            f.evidence = std::format("NT_GNU_PROPERTY_TYPE_0={}, AARCH64_BTI={}, AARCH64_PAC={}",
                                     props.found_note ? "present" : "absent",
                                     props.aarch64_bti ? 1 : 0,
                                     props.aarch64_pac ? 1 : 0);
        } else {
            f.severity = SecuritySeverity::Pass;
            f.summary = "CET/BTI GNU property notes are not required on this architecture.";
            f.evidence = std::format("Architecture={}", to_string(arch));
        }
        tally_finding(report, std::move(f));
    }

    report.status = SubsystemStatus::available(
        "security_audit",
        std::format("Evaluated 8 ELF security rules: {} error(s), {} warning(s), {} note(s), {} pass",
                    report.error_count,
                    report.warning_count,
                    report.note_count,
                    report.pass_count));
}

void evaluate_live_rules(IProcessSession& session,
                         const ProcessSecurityProfile* preloaded_profile,
                         SecurityAuditReport& report) {
    report.includes_live_process = true;

    std::vector<MemoryRegion> regions;
    bool regions_ok = false;
    if (auto regs = session.memory_regions(); regs.has_value()) {
        regions = std::move(*regs);
        regions_ok = true;
    }

    // LIVE3001: Live RWX memory regions (stack/heap/anonymous/module)
    {
        SecurityFinding f;
        f.rule_id = "LIVE3001";
        f.rule_name = "AvoidLiveReadWriteExecuteRegions";
        f.domain = SecurityRuleDomain::LiveProcess;
        f.subject = "VirtualMemory";
        f.remediation = "Transition JIT pages from RW to RX after code emission and keep stack/heap strictly RW.";

        if (!regions_ok) {
            f.severity = SecuritySeverity::Note;
            f.summary = "Live memory map unavailable for RWX audit.";
            f.evidence = "session.memory_regions() returned an error";
        } else {
            std::vector<const MemoryRegion*> rwx_regions;
            bool stack_or_heap_rwx = false;
            std::uint64_t total_rwx_bytes = 0u;
            for (const MemoryRegion& r : regions) {
                if (r.protection.readable && r.protection.writable && r.protection.executable) {
                    rwx_regions.push_back(&r);
                    total_rwx_bytes += r.size();
                    if (r.kind == MemoryRegionKind::Stack || r.kind == MemoryRegionKind::Heap) {
                        stack_or_heap_rwx = true;
                    }
                }
            }

            if (rwx_regions.empty()) {
                f.severity = SecuritySeverity::Pass;
                f.summary = "Zero live RWX virtual memory regions found in attached process.";
                f.evidence = std::format("Inspected {} virtual memory region(s); W^X holds across live address space.",
                                         regions.size());
            } else {
                f.severity = stack_or_heap_rwx ? SecuritySeverity::Error : SecuritySeverity::Warning;
                f.virtual_address = rwx_regions.front()->start_address;
                f.subject = rwx_regions.front()->pathname.empty()
                                ? std::string(to_string(rwx_regions.front()->kind))
                                : rwx_regions.front()->pathname;
                f.summary = std::format(
                    "Detected {} live RWX memory region(s) totaling 0x{:X} bytes{}.",
                    rwx_regions.size(),
                    total_rwx_bytes,
                    stack_or_heap_rwx ? " (includes RWX stack/heap!)" : "");
                std::string ev;
                for (std::size_t i = 0; i < std::min<std::size_t>(rwx_regions.size(), 4u); ++i) {
                    if (i > 0u) ev += "; ";
                    ev += std::format("0x{:X}-0x{:X} ({}, {})",
                                      rwx_regions[i]->start_address,
                                      rwx_regions[i]->end_address,
                                      to_string(rwx_regions[i]->kind),
                                      rwx_regions[i]->pathname.empty() ? "<anonymous>" : rwx_regions[i]->pathname);
                }
                f.evidence = std::move(ev);
            }
        }
        tally_finding(report, std::move(f));
    }

    // LIVE3002: Unbacked executable anonymous regions
    {
        SecurityFinding f;
        f.rule_id = "LIVE3002";
        f.rule_name = "InspectUnbackedExecutableMemory";
        f.domain = SecurityRuleDomain::LiveProcess;
        f.subject = "AnonymousExecMemory";
        f.remediation = "Audit anonymous executable mappings for JIT engines vs. reflective DLL / shellcode injection.";

        if (!regions_ok) {
            f.severity = SecuritySeverity::Note;
            f.summary = "Live memory map unavailable for unbacked-executable audit.";
            f.evidence = "session.memory_regions() returned an error";
        } else {
            std::vector<const MemoryRegion*> anon_exec;
            std::uint64_t total_bytes = 0u;
            for (const MemoryRegion& r : regions) {
                if (!r.protection.executable) continue;
                const bool kernel_special =
                    r.kind == MemoryRegionKind::Vdso ||
                    r.pathname == "[vdso]" || r.pathname == "[vsyscall]" || r.pathname == "[sigpage]";
                if (kernel_special) continue;
                if (r.pathname.empty() || r.kind == MemoryRegionKind::Anonymous ||
                    r.kind == MemoryRegionKind::Heap || r.kind == MemoryRegionKind::Stack) {
                    anon_exec.push_back(&r);
                    total_bytes += r.size();
                }
            }

            if (anon_exec.empty()) {
                f.severity = SecuritySeverity::Pass;
                f.summary = "All executable live memory regions are backed by mapped files or kernel vDSO.";
                f.evidence = std::format("Inspected {} region(s); zero unbacked anonymous executable mappings.",
                                         regions.size());
            } else {
                f.severity = SecuritySeverity::Warning;
                f.virtual_address = anon_exec.front()->start_address;
                f.summary = std::format("Found {} unbacked executable memory region(s) (0x{:X} bytes).",
                                        anon_exec.size(),
                                        total_bytes);
                std::string ev;
                for (std::size_t i = 0; i < std::min<std::size_t>(anon_exec.size(), 4u); ++i) {
                    if (i > 0u) ev += "; ";
                    ev += std::format("0x{:X}-0x{:X} ({}{}{})",
                                      anon_exec[i]->start_address,
                                      anon_exec[i]->end_address,
                                      anon_exec[i]->protection.readable ? "r" : "-",
                                      anon_exec[i]->protection.writable ? "w" : "-",
                                      anon_exec[i]->protection.executable ? "x" : "-");
                }
                f.evidence = std::move(ev);
            }
        }
        tally_finding(report, std::move(f));
    }

    // LIVE3003: Disabled process ASLR/DEP/Seccomp from `ProcessSecurityProfile`
    {
        std::optional<ProcessSecurityProfile> fetched_profile;
        const ProcessSecurityProfile* prof = preloaded_profile;
        if (prof == nullptr) {
            auto snap = inspect_process_internals(session);
            if (snap.security.has_value()) {
                fetched_profile = std::move(*snap.security.value);
                prof = &*fetched_profile;
            }
        }

        SecurityFinding f;
        f.rule_id = "LIVE3003";
        f.rule_name = "VerifyProcessRuntimeMitigations";
        f.domain = SecurityRuleDomain::LiveProcess;
        f.subject = "ProcessSecurityProfile";
        f.remediation = "Ensure OS-level ASLR and DEP are enabled and restrict untrusted workloads with Seccomp + NoNewPrivs.";

        if (prof == nullptr) {
            f.severity = SecuritySeverity::Note;
            f.summary = "ProcessSecurityProfile telemetry is unavailable for the attached process.";
            f.evidence = "Insufficient OS privileges or unsupported session backend for security profile query.";
        } else {
            bool dep_or_aslr_disabled = false;
            std::vector<std::string> disabled_policies;
            for (const ProcessMitigationEntry& m : prof->mitigations) {
                const std::string low = lower_ascii(m.policy);
                if (!m.enabled &&
                    (low.find("dep") != std::string::npos ||
                     low.find("aslr") != std::string::npos ||
                     low.find("bottom-up") != std::string::npos)) {
                    dep_or_aslr_disabled = true;
                    disabled_policies.push_back(std::format("{}={}", m.policy, m.state));
                }
            }

            const std::string seccomp_low = lower_ascii(prof->seccomp_mode);
            const bool seccomp_disabled =
                !prof->seccomp_mode.empty() &&
                (prof->seccomp_mode == "0" || seccomp_low.starts_with("0 ") ||
                 seccomp_low.find("disabled") != std::string::npos);

            if (dep_or_aslr_disabled) {
                f.severity = SecuritySeverity::Error;
                f.summary = "Critical process runtime mitigation (DEP or ASLR) is disabled.";
            } else if (seccomp_disabled) {
                f.severity = SecuritySeverity::Warning;
                f.summary = "Process is running without a Seccomp syscall filter.";
            } else {
                f.severity = SecuritySeverity::Pass;
                f.summary = "Process runtime mitigation profile shows active OS protections.";
            }

            std::string ev = std::format("Seccomp='{}', NoNewPrivs={}, Mitigations={}",
                                         prof->seccomp_mode.empty() ? "n/a" : prof->seccomp_mode,
                                         prof->no_new_privs.has_value() ? (*prof->no_new_privs ? "1" : "0") : "n/a",
                                         prof->mitigations.size());
            for (const std::string& dp : disabled_policies) {
                ev += "; disabled: " + dp;
            }
            f.evidence = std::move(ev);
        }
        tally_finding(report, std::move(f));
    }
}

// ---------------------------------------------------------------------------
// JSON Escaping & Atomic File Write Helpers
// ---------------------------------------------------------------------------

void append_json_escaped(std::string& out, std::string_view text) {
    out.push_back('"');
    for (const char raw_ch : text) {
        const auto c = static_cast<unsigned char>(raw_ch);
        switch (c) {
            case '"':  out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\b': out += "\\b"; break;
            case '\f': out += "\\f"; break;
            case '\n': out += "\\n"; break;
            case '\r': out += "\\r"; break;
            case '\t': out += "\\t"; break;
            default:
                if (c < 0x20u) {
                    out += std::format("\\u{:04x}", static_cast<unsigned int>(c));
                } else {
                    out.push_back(static_cast<char>(c));
                }
                break;
        }
    }
    out.push_back('"');
}

[[nodiscard]] Result<void> write_text_file_atomically(
    const std::filesystem::path& output_path,
    std::string_view content) {
    std::error_code ec;
    const std::filesystem::path parent = output_path.parent_path();
    if (!parent.empty()) {
        std::filesystem::create_directories(parent, ec);
        if (ec) {
            return make_error(std::format("Failed to create parent directory '{}': {}",
                                          parent.string(),
                                          ec.message()));
        }
    }

#ifdef _WIN32
    const int pid = _getpid();
#else
    const int pid = static_cast<int>(::getpid());
#endif
    const std::filesystem::path tmp_path =
        output_path.string() + std::format(".tmp.{}", pid);

    {
        std::ofstream ofs(tmp_path, std::ios::binary | std::ios::trunc);
        if (!ofs) {
            return make_error(std::format("Failed to open temporary output file '{}'",
                                          tmp_path.string()));
        }
        ofs.write(content.data(), static_cast<std::streamsize>(content.size()));
        ofs.flush();
        if (!ofs) {
            ofs.close();
            std::filesystem::remove(tmp_path, ec);
            return make_error(std::format("Failed while writing temporary output file '{}'",
                                          tmp_path.string()));
        }
    }

    std::filesystem::rename(tmp_path, output_path, ec);
    if (ec) {
        std::filesystem::remove(output_path, ec);
        ec.clear();
        std::filesystem::rename(tmp_path, output_path, ec);
        if (ec) {
            std::error_code rm_ec;
            std::filesystem::remove(tmp_path, rm_ec);
            return make_error(std::format("Failed to commit output file '{}': {}",
                                          output_path.string(),
                                          ec.message()));
        }
    }
    return {};
}

[[nodiscard]] bool is_printable_ascii_char(std::uint8_t b) noexcept {
    return (b >= 0x20u && b <= 0x7Eu) || b == '\t';
}

} // namespace

std::span<const SecurityRuleDescriptor> security_rule_catalog() noexcept {
    return kRuleCatalog;
}

SecurityAuditReport audit_security(
    const IBinaryImage& image,
    std::span<const std::uint8_t> raw_bytes,
    IProcessSession* live_session,
    const ProcessSecurityProfile* preloaded_security_profile) {
    SecurityAuditReport report;
    report.target_format = image.format();

    if (image.format() == Format::PE) {
        evaluate_pe_rules(image, raw_bytes, report);
    } else if (image.format() == Format::ELF) {
        evaluate_elf_rules(image, report);
    } else {
        report.status = SubsystemStatus::unavailable("security_audit", "Unsupported binary format");
    }

    if (live_session != nullptr) {
        evaluate_live_rules(*live_session, preloaded_security_profile, report);
        report.status = SubsystemStatus::available(
            "security_audit",
            std::format("Evaluated static + live security rules: {} error(s), {} warning(s), {} note(s), {} pass",
                        report.error_count,
                        report.warning_count,
                        report.note_count,
                        report.pass_count));
    }

    return report;
}

SecurityAuditReport audit_live_process_security(
    IProcessSession& session,
    const ProcessSecurityProfile* preloaded_security_profile) {
    SecurityAuditReport report;
    evaluate_live_rules(session, preloaded_security_profile, report);
    report.status = SubsystemStatus::available(
        "security_audit",
        std::format("Evaluated 3 live-process security rules: {} error(s), {} warning(s), {} note(s), {} pass",
                    report.error_count,
                    report.warning_count,
                    report.note_count,
                    report.pass_count));
    return report;
}

// ---------------------------------------------------------------------------
// Headless String Extraction, Analysis & JSON / SARIF Serialization
// ---------------------------------------------------------------------------

std::vector<HeadlessExtractedString> extract_headless_strings(
    const IBinaryImage& image,
    std::span<const std::uint8_t> raw_bytes,
    std::size_t min_length,
    std::size_t max_strings) {
    const std::size_t min_len = std::max<std::size_t>(min_length, 1u);
    std::vector<HeadlessExtractedString> out;
    if (raw_bytes.empty() || max_strings == 0u) {
        return out;
    }

    struct ScanSpan {
        std::string name{};
        std::uint64_t file_offset{0};
        std::uint64_t size{0};
        std::uint64_t base_va{0};
    };

    std::vector<ScanSpan> spans;
    for (const Section& sec : image.sections()) {
        if (sec.file_size == 0u || sec.file_offset >= raw_bytes.size()) continue;
        const std::uint64_t avail = std::min<std::uint64_t>(sec.file_size, raw_bytes.size() - sec.file_offset);
        spans.push_back(ScanSpan{sec.name, sec.file_offset, avail, sec.virtual_address});
    }
    if (spans.empty()) {
        spans.push_back(ScanSpan{"<file>", 0u, raw_bytes.size(), image.image_base()});
    }

    for (const ScanSpan& sp : spans) {
        const auto buf = raw_bytes.subspan(static_cast<std::size_t>(sp.file_offset),
                                           static_cast<std::size_t>(sp.size));

        // 1. Printable ASCII runs
        std::size_t i = 0u;
        while (i < buf.size() && out.size() < max_strings) {
            if (!is_printable_ascii_char(buf[i])) {
                ++i;
                continue;
            }
            const std::size_t start = i;
            while (i < buf.size() && (i - start) < 2048u && is_printable_ascii_char(buf[i])) {
                ++i;
            }
            const std::size_t len = i - start;
            if (len >= min_len) {
                HeadlessExtractedString item;
                item.value.assign(reinterpret_cast<const char*>(buf.data() + start), len);
                item.encoding = "ASCII";
                item.section_name = sp.name;
                item.file_offset = sp.file_offset + start;
                item.virtual_address = sp.base_va + start;
                item.byte_length = len;
                out.push_back(std::move(item));
            }
        }

        // 2. UTF-16LE Basic Latin runs (common in PE resources/rdata)
        std::size_t u = 0u;
        while (u + 1u < buf.size() && out.size() < max_strings) {
            if (!is_printable_ascii_char(buf[u]) || buf[u + 1u] != 0u) {
                ++u;
                continue;
            }
            const std::size_t start = u;
            std::string decoded;
            while (u + 1u < buf.size() && decoded.size() < 2048u &&
                   is_printable_ascii_char(buf[u]) && buf[u + 1u] == 0u) {
                decoded.push_back(static_cast<char>(buf[u]));
                u += 2u;
            }
            if (decoded.size() >= min_len) {
                HeadlessExtractedString item;
                item.value = std::move(decoded);
                item.encoding = "UTF-16LE";
                item.section_name = sp.name;
                item.file_offset = sp.file_offset + start;
                item.virtual_address = sp.base_va + start;
                item.byte_length = u - start;
                out.push_back(std::move(item));
            }
        }

        if (out.size() >= max_strings) {
            break;
        }
    }

    return out;
}

Result<HeadlessAnalysisReport> analyze_binary_headless(const HeadlessCliOptions& options) {
    if (options.binary_path.empty()) {
        return make_error("No input binary path specified");
    }

    std::ifstream ifs(options.binary_path, std::ios::binary | std::ios::ate);
    if (!ifs) {
        return make_error(std::format("Failed to open binary '{}'", options.binary_path.string()));
    }
    const auto end_pos = ifs.tellg();
    if (end_pos < 0) {
        return make_error(std::format("Failed to determine file size of '{}'", options.binary_path.string()));
    }

    std::vector<std::uint8_t> raw_bytes(static_cast<std::size_t>(end_pos));
    ifs.seekg(0, std::ios::beg);
    if (!raw_bytes.empty() &&
        !ifs.read(reinterpret_cast<char*>(raw_bytes.data()),
                  static_cast<std::streamsize>(raw_bytes.size()))) {
        return make_error(std::format("Failed while reading '{}'", options.binary_path.string()));
    }

    auto parsed = parse_image(raw_bytes);
    if (!parsed.has_value()) {
        return make_error(std::format("Failed to parse '{}': {}",
                                      options.binary_path.string(),
                                      parsed.error().message));
    }

    HeadlessAnalysisReport report;
    report.binary_path = options.binary_path;
    report.sha256 = sha256_hex(raw_bytes);
    report.file_size = raw_bytes.size();
    report.image = std::move(*parsed);

    DependencyResolveOptions dep_opts;
    dep_opts.root_path = options.binary_path;
    dep_opts.search_roots = options.search_roots;
    report.dependencies = build_dependency_graph(*report.image, dep_opts);

    report.security = audit_security(*report.image, raw_bytes);

    if (options.include_strings) {
        report.strings_included = true;
        report.strings = extract_headless_strings(
            *report.image, raw_bytes, options.min_string_length, options.max_strings);
    }

    if (options.compare_path.has_value()) {
        BinaryDiffOptions diff_opts;
        diff_opts.lhs_label = options.binary_path.filename().string();
        diff_opts.rhs_label = options.compare_path->filename().string();
        auto cmp = compare_binary_files(options.binary_path, *options.compare_path, diff_opts);
        if (!cmp.has_value()) {
            return std::unexpected(cmp.error());
        }
        report.comparison = std::move(*cmp);
    }

    return report;
}

std::string format_headless_report_json(const HeadlessAnalysisReport& report) {
    const IBinaryImage& img = *report.image;
    std::string out;
    out.reserve(16384u);

    auto key = [&](std::string_view k) {
        append_json_escaped(out, k);
        out += ": ";
    };

    out += "{\n";
    out += "  \"schema_version\": 1,\n";

    // Binary identity
    out += "  \"binary\": {\n";
    out += "    "; key("path"); append_json_escaped(out, report.binary_path.generic_string()); out += ",\n";
    out += "    "; key("sha256"); append_json_escaped(out, report.sha256); out += ",\n";
    out += std::format("    \"size\": {},\n", report.file_size);
    out += "    "; key("format"); append_json_escaped(out, to_string(img.format())); out += ",\n";
    out += "    "; key("kind"); append_json_escaped(out, to_string(img.kind())); out += ",\n";
    out += "    "; key("arch"); append_json_escaped(out, to_string(img.architecture())); out += ",\n";
    out += std::format("    \"bits\": {},\n", img.is_64bit() ? 64 : 32);
    out += "    "; key("endianness"); append_json_escaped(out, to_string(img.endianness())); out += ",\n";
    out += std::format("    \"entry_point\": {},\n", img.entry_point());
    out += std::format("    \"image_base\": {}\n", img.image_base());
    out += "  },\n";

    // Sections
    out += "  \"sections\": [";
    const auto& secs = img.sections();
    for (std::size_t i = 0; i < secs.size(); ++i) {
        const Section& s = secs[i];
        out += (i == 0u) ? "\n" : ",\n";
        out += "    { ";
        key("name"); append_json_escaped(out, s.name);
        out += std::format(", \"virtual_address\": {}, \"virtual_size\": {}, \"file_offset\": {}, \"file_size\": {}, \"raw_flags\": {}, \"readable\": {}, \"writable\": {}, \"executable\": {} }}",
                           s.virtual_address,
                           s.virtual_size,
                           s.file_offset,
                           s.file_size,
                           s.raw_flags,
                           s.readable ? "true" : "false",
                           s.writable ? "true" : "false",
                           s.executable ? "true" : "false");
    }
    if (!secs.empty()) out += "\n  ";
    out += "],\n";

    // Imports
    out += "  \"imports\": [";
    const auto& imps = img.imports();
    for (std::size_t i = 0; i < imps.size(); ++i) {
        const ImportEntry& imp = imps[i];
        out += (i == 0u) ? "\n" : ",\n";
        out += "    { ";
        key("library"); append_json_escaped(out, imp.library); out += ", ";
        key("name"); append_json_escaped(out, imp.name);
        out += std::format(", \"ordinal\": {}, \"address\": {}, \"import_by_ordinal\": {}, \"delay_load\": {} }}",
                           imp.ordinal,
                           imp.address,
                           imp.import_by_ordinal ? "true" : "false",
                           imp.delay_load ? "true" : "false");
    }
    if (!imps.empty()) out += "\n  ";
    out += "],\n";

    // Exports
    out += "  \"exports\": [";
    const auto& exps = img.exports();
    for (std::size_t i = 0; i < exps.size(); ++i) {
        const ExportEntry& exp = exps[i];
        out += (i == 0u) ? "\n" : ",\n";
        out += "    { ";
        key("name"); append_json_escaped(out, exp.name);
        out += std::format(", \"ordinal\": {}, \"virtual_address\": {}, ", exp.ordinal, exp.virtual_address);
        key("forwarder"); append_json_escaped(out, exp.forwarder);
        out += " }";
    }
    if (!exps.empty()) out += "\n  ";
    out += "],\n";

    // Dependency resolution (`WU-10`)
    const DependencySummary& ds = report.dependencies.summary;
    out += "  \"dependencies\": {\n";
    out += std::format("    \"direct_dependencies\": {},\n", ds.direct_dependencies);
    out += std::format("    \"transitive_dependencies\": {},\n", ds.transitive_dependencies);
    out += std::format("    \"resolved_count\": {},\n", ds.resolved_count);
    out += std::format("    \"virtual_api_sets\": {},\n", ds.virtual_api_sets);
    out += std::format("    \"missing_libraries\": {},\n", ds.missing_libraries);
    out += std::format("    \"architecture_mismatches\": {},\n", ds.architecture_mismatches);
    out += std::format("    \"cycle_edges\": {},\n", ds.cycle_edges);
    out += std::format("    \"unresolved_symbols\": {},\n", ds.unresolved_symbols);
    out += "    \"nodes\": [";
    for (std::size_t i = 0; i < report.dependencies.nodes.size(); ++i) {
        const DependencyNode& n = report.dependencies.nodes[i];
        out += (i == 0u) ? "\n" : ",\n";
        out += "      { ";
        key("requested_name"); append_json_escaped(out, n.requested_name); out += ", ";
        key("status"); append_json_escaped(out, to_string(n.status)); out += ", ";
        key("resolved_path"); append_json_escaped(out, n.resolved_path.generic_string()); out += ", ";
        key("resolution_reason"); append_json_escaped(out, n.resolution_reason);
        out += std::format(", \"unresolved_symbol_count\": {} }}", n.unresolved_symbols.size());
    }
    if (!report.dependencies.nodes.empty()) out += "\n    ";
    out += "]\n  },\n";

    // Symbols with demangled names (`WU-05`)
    out += "  \"symbols\": [";
    const auto& syms = img.symbols();
    for (std::size_t i = 0; i < syms.size(); ++i) {
        const Symbol& s = syms[i];
        const DemangleResult dem = demangle_symbol(s.name);
        out += (i == 0u) ? "\n" : ",\n";
        out += "    { ";
        key("name"); append_json_escaped(out, s.name); out += ", ";
        key("demangled_name"); append_json_escaped(out, dem.succeeded ? dem.demangled : s.name); out += ", ";
        key("mangling_scheme"); append_json_escaped(out, to_string(dem.scheme));
        out += std::format(", \"virtual_address\": {}, \"size\": {}, \"binding\": {}, \"type\": {}, \"dynamic\": {} }}",
                           s.virtual_address,
                           s.size,
                           s.binding,
                           s.type,
                           s.dynamic ? "true" : "false");
    }
    if (!syms.empty()) out += "\n  ";
    out += "],\n";

    // Security Audit (`WU-13`)
    out += "  \"security_audit\": {\n";
    out += std::format("    \"pass_count\": {},\n", report.security.pass_count);
    out += std::format("    \"note_count\": {},\n", report.security.note_count);
    out += std::format("    \"warning_count\": {},\n", report.security.warning_count);
    out += std::format("    \"error_count\": {},\n", report.security.error_count);
    out += "    \"findings\": [";
    for (std::size_t i = 0; i < report.security.findings.size(); ++i) {
        const SecurityFinding& f = report.security.findings[i];
        out += (i == 0u) ? "\n" : ",\n";
        out += "      { ";
        key("rule_id"); append_json_escaped(out, f.rule_id); out += ", ";
        key("rule_name"); append_json_escaped(out, f.rule_name); out += ", ";
        key("domain"); append_json_escaped(out, to_string(f.domain)); out += ", ";
        key("severity"); append_json_escaped(out, to_string(f.severity)); out += ", ";
        key("subject"); append_json_escaped(out, f.subject); out += ", ";
        key("summary"); append_json_escaped(out, f.summary); out += ", ";
        key("evidence"); append_json_escaped(out, f.evidence); out += ", ";
        key("remediation"); append_json_escaped(out, f.remediation); out += ", ";
        out += "\"virtual_address\": ";
        out += f.virtual_address.has_value() ? std::to_string(*f.virtual_address) : "null";
        out += ", \"file_offset\": ";
        out += f.file_offset.has_value() ? std::to_string(*f.file_offset) : "null";
        out += " }";
    }
    if (!report.security.findings.empty()) out += "\n    ";
    out += "]\n  }";

    // Optional strings (`--include-strings`)
    if (report.strings_included) {
        out += ",\n  \"strings\": [";
        for (std::size_t i = 0; i < report.strings.size(); ++i) {
            const HeadlessExtractedString& st = report.strings[i];
            out += (i == 0u) ? "\n" : ",\n";
            out += "    { ";
            key("value"); append_json_escaped(out, st.value); out += ", ";
            key("encoding"); append_json_escaped(out, st.encoding); out += ", ";
            key("section"); append_json_escaped(out, st.section_name);
            out += std::format(", \"virtual_address\": {}, \"file_offset\": {}, \"byte_length\": {} }}",
                               st.virtual_address,
                               st.file_offset,
                               st.byte_length);
        }
        if (!report.strings.empty()) out += "\n  ";
        out += "]";
    }

    // Optional binary comparison (`--compare` from `WU-12`)
    if (report.comparison.has_value()) {
        const BinaryDiffReport& c = *report.comparison;
        out += ",\n  \"comparison\": {\n";
        out += "    "; key("lhs_label"); append_json_escaped(out, c.header.lhs_label); out += ",\n";
        out += "    "; key("rhs_label"); append_json_escaped(out, c.header.rhs_label); out += ",\n";
        out += std::format("    \"identical_files\": {},\n", c.header.identical_files ? "true" : "false");
        out += "    "; key("lhs_sha256"); append_json_escaped(out, c.header.lhs_sha256); out += ",\n";
        out += "    "; key("rhs_sha256"); append_json_escaped(out, c.header.rhs_sha256); out += ",\n";
        out += std::format("    \"sections_added\": {},\n", c.sections_added);
        out += std::format("    \"sections_removed\": {},\n", c.sections_removed);
        out += std::format("    \"sections_modified\": {},\n", c.sections_modified);
        out += std::format("    \"sections_unchanged\": {},\n", c.sections_unchanged);
        out += std::format("    \"imports_added\": {},\n", c.imports_added);
        out += std::format("    \"imports_removed\": {},\n", c.imports_removed);
        out += std::format("    \"exports_added\": {},\n", c.exports_added);
        out += std::format("    \"exports_removed\": {},\n", c.exports_removed);
        out += std::format("    \"exports_modified\": {},\n", c.exports_modified);
        out += std::format("    \"functions_identical\": {},\n", c.functions_identical);
        out += std::format("    \"functions_relocated_identical\": {},\n", c.functions_relocated);
        out += std::format("    \"functions_modified\": {},\n", c.functions_modified);
        out += std::format("    \"functions_added\": {},\n", c.functions_added);
        out += std::format("    \"functions_removed\": {},\n", c.functions_removed);
        out += std::format("    \"total_changed_bytes\": {},\n", c.total_changed_bytes);
        out += "    \"functions\": [";
        for (std::size_t i = 0; i < c.functions.size(); ++i) {
            const FunctionDiffEntry& fn = c.functions[i];
            out += (i == 0u) ? "\n" : ",\n";
            out += "      { ";
            key("display_name"); append_json_escaped(out, fn.display_name); out += ", ";
            key("status"); append_json_escaped(out, to_string(fn.status)); out += ", ";
            key("match_basis"); append_json_escaped(out, fn.match_basis);
            out += std::format(", \"similarity\": {:.4f}, \"size_delta\": {}, \"lhs_va\": {}, \"rhs_va\": {} }}",
                               fn.similarity,
                               fn.size_delta,
                               fn.lhs_va.has_value() ? std::to_string(*fn.lhs_va) : "null",
                               fn.rhs_va.has_value() ? std::to_string(*fn.rhs_va) : "null");
        }
        if (!c.functions.empty()) out += "\n    ";
        out += "]\n  }";
    }

    out += "\n}\n";
    return out;
}

std::string format_headless_report_sarif(const HeadlessAnalysisReport& report) {
    std::string out;
    out.reserve(12288u);

    auto key = [&](std::string_view k) {
        append_json_escaped(out, k);
        out += ": ";
    };

    const auto catalog = security_rule_catalog();
    std::unordered_map<std::string_view, std::size_t> rule_index_by_id;
    std::vector<SecurityRuleDescriptor> active_rules;
    for (const SecurityFinding& f : report.security.findings) {
        for (const SecurityRuleDescriptor& desc : catalog) {
            if (desc.id == f.rule_id && !rule_index_by_id.contains(desc.id)) {
                rule_index_by_id.emplace(desc.id, active_rules.size());
                active_rules.push_back(desc);
                break;
            }
        }
    }

    auto sarif_level = [](SecuritySeverity sev) noexcept -> std::string_view {
        switch (sev) {
            case SecuritySeverity::Pass:    return "none";
            case SecuritySeverity::Note:    return "note";
            case SecuritySeverity::Warning: return "warning";
            case SecuritySeverity::Error:   return "error";
        }
        return "note";
    };

    const std::string artifact_uri = report.binary_path.generic_string();

    out += "{\n";
    out += "  \"$schema\": \"https://json.schemastore.org/sarif-2.1.0.json\",\n";
    out += "  \"version\": \"2.1.0\",\n";
    out += "  \"runs\": [\n";
    out += "    {\n";
    out += "      \"tool\": {\n";
    out += "        \"driver\": {\n";
    out += "          \"name\": \"peelf_viewer\",\n";
    out += "          \"version\": \"0.0.1\",\n";
    out += "          \"informationUri\": \"https://github.com/wsollers/exe_viewer\",\n";
    out += "          \"rules\": [";
    for (std::size_t i = 0; i < active_rules.size(); ++i) {
        const SecurityRuleDescriptor& r = active_rules[i];
        out += (i == 0u) ? "\n" : ",\n";
        out += "            {\n";
        out += "              "; key("id"); append_json_escaped(out, r.id); out += ",\n";
        out += "              "; key("name"); append_json_escaped(out, r.name); out += ",\n";
        out += "              \"shortDescription\": { "; key("text"); append_json_escaped(out, r.short_description); out += " },\n";
        out += "              \"help\": { "; key("text"); append_json_escaped(out, r.help_text); out += " },\n";
        out += "              \"defaultConfiguration\": { ";
        key("level"); append_json_escaped(out, sarif_level(r.default_failure_severity));
        out += " }\n";
        out += "            }";
    }
    if (!active_rules.empty()) out += "\n          ";
    out += "]\n";
    out += "        }\n";
    out += "      },\n";

    // Artifacts
    out += "      \"artifacts\": [\n";
    out += "        {\n";
    out += "          \"location\": { "; key("uri"); append_json_escaped(out, artifact_uri); out += " },\n";
    out += std::format("          \"length\": {},\n", report.file_size);
    out += "          \"hashes\": { "; key("sha-256"); append_json_escaped(out, report.sha256); out += " }\n";
    out += "        }\n";
    out += "      ],\n";

    // Results
    out += "      \"results\": [";
    for (std::size_t i = 0; i < report.security.findings.size(); ++i) {
        const SecurityFinding& f = report.security.findings[i];
        out += (i == 0u) ? "\n" : ",\n";
        out += "        {\n";
        out += "          "; key("ruleId"); append_json_escaped(out, f.rule_id); out += ",\n";
        if (auto it = rule_index_by_id.find(f.rule_id); it != rule_index_by_id.end()) {
            out += std::format("          \"ruleIndex\": {},\n", it->second);
        }
        if (f.severity == SecuritySeverity::Pass) {
            out += "          \"kind\": \"pass\",\n";
            out += "          \"level\": \"none\",\n";
        } else {
            out += "          \"kind\": \"fail\",\n";
            out += "          "; key("level"); append_json_escaped(out, sarif_level(f.severity)); out += ",\n";
        }
        const std::string msg = std::format("{} Evidence: {} Remediation: {}",
                                            f.summary,
                                            f.evidence,
                                            f.remediation);
        out += "          \"message\": { "; key("text"); append_json_escaped(out, msg); out += " },\n";
        out += "          \"locations\": [\n";
        out += "            {\n";
        out += "              \"physicalLocation\": {\n";
        out += "                \"artifactLocation\": { ";
        key("uri"); append_json_escaped(out, artifact_uri);
        out += ", \"index\": 0 }";
        if (f.virtual_address.has_value() || f.file_offset.has_value() || !f.subject.empty()) {
            out += ",\n                \"address\": { ";
            bool need_comma = false;
            if (f.virtual_address.has_value()) {
                out += std::format("\"absoluteAddress\": {}", *f.virtual_address);
                need_comma = true;
            }
            if (f.file_offset.has_value()) {
                if (need_comma) out += ", ";
                out += std::format("\"offsetFromParent\": {}", *f.file_offset);
                need_comma = true;
            }
            if (!f.subject.empty()) {
                if (need_comma) out += ", ";
                key("name"); append_json_escaped(out, f.subject);
            }
            out += " }";
        }
        out += "\n              }\n";
        out += "            }\n";
        out += "          ]\n";
        out += "        }";
    }
    if (!report.security.findings.empty()) out += "\n      ";
    out += "]";

    // Optional properties block carrying dependency & comparison summary for CI tooling
    out += ",\n      \"properties\": {\n";
    out += std::format("        \"missingLibraries\": {},\n", report.dependencies.summary.missing_libraries);
    out += std::format("        \"architectureMismatches\": {},\n", report.dependencies.summary.architecture_mismatches);
    out += std::format("        \"unresolvedSymbols\": {}", report.dependencies.summary.unresolved_symbols);
    if (report.comparison.has_value()) {
        out += std::format(",\n        \"comparisonIdenticalFiles\": {},\n",
                           report.comparison->header.identical_files ? "true" : "false");
        out += std::format("        \"comparisonModifiedFunctions\": {}",
                           report.comparison->functions_modified);
    }
    out += "\n      }\n";

    out += "    }\n";
    out += "  ]\n";
    out += "}\n";
    return out;
}

int evaluate_headless_policy_exit_code(
    const HeadlessAnalysisReport& report,
    HeadlessFailPolicy fail_on) noexcept {
    if (fail_on == HeadlessFailPolicy::None) {
        return 0;
    }

    const DependencySummary& ds = report.dependencies.summary;
    const bool has_dep_errors =
        ds.missing_libraries > 0u ||
        ds.architecture_mismatches > 0u ||
        ds.unresolved_symbols > 0u;

    if (fail_on == HeadlessFailPolicy::Error) {
        if (report.security.error_count > 0u || has_dep_errors) {
            return 2;
        }
        return 0;
    }

    if (fail_on == HeadlessFailPolicy::Warning) {
        if (report.security.error_count > 0u ||
            report.security.warning_count > 0u ||
            has_dep_errors) {
            return 2;
        }
        return 0;
    }

    return 0;
}

std::optional<int> try_run_headless_or_help_cli(
    std::span<const std::string_view> args,
    std::ostream& stdout_stream,
    std::ostream& stderr_stream) {
    bool headless = false;
    bool help = false;
    for (std::string_view arg : args) {
        if (arg == "--headless") headless = true;
        if (arg == "--help" || arg == "-h") help = true;
    }

    if (help) {
        stdout_stream
            << "PE/ELF Explorer\n"
            << "Usage:\n"
            << "  peelf_viewer                                  Launch Vulkan/ImGui desktop viewer\n"
            << "  peelf_viewer --headless                       Smoke check without loading GUI (exits 0)\n"
            << "  peelf_viewer --headless <binary> [options]    Run headless static & security inspection\n"
            << "\nHeadless Options:\n"
            << "  --compare <other_binary>     Include static binary & relocation-tolerant function diff\n"
            << "  --format <json|sarif>        Output format (default: json; sarif emits SARIF 2.1.0)\n"
            << "  --output <path>              Write report atomically to <path> (default: stdout)\n"
            << "  --search-root <dir>          Extra dependency search directory (repeatable)\n"
            << "  --include-strings            Include extracted printable ASCII/UTF-16 strings\n"
            << "  --min-string-len <N>         Minimum character length for extracted strings (default: 4)\n"
            << "  --fail-on <none|error|warning>\n"
            << "                               CI policy gate (exit 2 on security findings or missing deps)\n"
            << "  --help                       Show this help\n";
        return 0;
    }

    if (!headless) {
        return std::nullopt;
    }

    HeadlessCliOptions opts;
    bool has_positional_binary = false;

    for (std::size_t i = 0; i < args.size(); ++i) {
        const std::string_view a = args[i];
        if (a == "--headless") {
            continue;
        }
        auto require_next = [&](std::string_view flag) -> std::optional<std::string_view> {
            if (i + 1u >= args.size()) {
                stderr_stream << "Error: missing value after " << flag << "\n";
                return std::nullopt;
            }
            return args[++i];
        };

        if (a == "--compare") {
            auto val = require_next(a);
            if (!val) return 1;
            opts.compare_path = std::filesystem::path(*val);
        } else if (a == "--format") {
            auto val = require_next(a);
            if (!val) return 1;
            const std::string low = lower_ascii(*val);
            if (low == "json") {
                opts.format = HeadlessExportFormat::Json;
            } else if (low == "sarif") {
                opts.format = HeadlessExportFormat::Sarif;
            } else {
                stderr_stream << "Error: unsupported --format '" << *val << "' (expected json or sarif)\n";
                return 1;
            }
        } else if (a == "--output") {
            auto val = require_next(a);
            if (!val) return 1;
            opts.output_path = std::filesystem::path(*val);
        } else if (a == "--search-root") {
            auto val = require_next(a);
            if (!val) return 1;
            opts.search_roots.emplace_back(*val);
        } else if (a == "--include-strings") {
            opts.include_strings = true;
        } else if (a == "--min-string-len") {
            auto val = require_next(a);
            if (!val) return 1;
            std::size_t parsed_len = 0u;
            const auto [ptr, ec] = std::from_chars(val->data(), val->data() + val->size(), parsed_len);
            if (ec != std::errc{} || ptr != val->data() + val->size() || parsed_len == 0u) {
                stderr_stream << "Error: invalid --min-string-len '" << *val << "' (expected positive integer)\n";
                return 1;
            }
            opts.min_string_length = parsed_len;
        } else if (a == "--fail-on") {
            auto val = require_next(a);
            if (!val) return 1;
            const std::string low = lower_ascii(*val);
            if (low == "none") {
                opts.fail_on = HeadlessFailPolicy::None;
            } else if (low == "error") {
                opts.fail_on = HeadlessFailPolicy::Error;
            } else if (low == "warning") {
                opts.fail_on = HeadlessFailPolicy::Warning;
            } else {
                stderr_stream << "Error: unsupported --fail-on '" << *val << "' (expected none, error, or warning)\n";
                return 1;
            }
        } else if (a.starts_with('-')) {
            stderr_stream << "Error: unknown headless option '" << a << "'\n";
            return 1;
        } else if (!has_positional_binary) {
            opts.binary_path = std::filesystem::path(a);
            has_positional_binary = true;
        } else {
            stderr_stream << "Error: unexpected extra positional argument '" << a << "'\n";
            return 1;
        }
    }

    // Bare `peelf_viewer --headless` (no input binary) exits 0 cleanly for smoke tests!
    if (!has_positional_binary) {
        return 0;
    }

    auto analysis = analyze_binary_headless(opts);
    if (!analysis.has_value()) {
        stderr_stream << "Error: " << analysis.error().message << "\n";
        return 1;
    }

    const std::string serialized =
        (opts.format == HeadlessExportFormat::Sarif)
            ? format_headless_report_sarif(*analysis)
            : format_headless_report_json(*analysis);

    if (opts.output_path.has_value()) {
        if (auto wr = write_text_file_atomically(*opts.output_path, serialized); !wr.has_value()) {
            stderr_stream << "Error: " << wr.error().message << "\n";
            return 1;
        }
    } else {
        stdout_stream << serialized;
        stdout_stream.flush();
    }

    return evaluate_headless_policy_exit_code(*analysis, opts.fail_on);
}

} // namespace peelf
