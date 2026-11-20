#include <peelf/security_audit.hpp>

#include "atomic_file_writer.hpp"

#include <peelf/demangle.hpp>
#include <peelf/endian_reader.hpp>
#include <peelf/macho_image.hpp>
#include <peelf/sha256.hpp>

#include <algorithm>
#include <array>
#include <cctype>
#include <charconv>
#include <cstring>
#include <filesystem>
#include <format>
#include <fstream>
#include <iostream>
#include <set>
#include <sstream>
#include <string>
#include <string_view>
#include <unordered_map>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <softpub.h>
#include <wincrypt.h>
#include <wintrust.h>
#endif

namespace peelf {
namespace {

constexpr std::array<SecurityRuleDescriptor, 25> kRuleCatalog = {{
    {"PE1001", "EnableAddressSpaceLayoutRandomization", SecurityRuleDomain::PE, SecuritySeverity::Error,
     "PE binaries must enable DYNAMIC_BASE without IMAGE_FILE_RELOCS_STRIPPED (and HIGH_ENTROPY_VA on 64-bit targets).",
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

    {"MACHO4001", "EnablePieAndZeroPage", SecurityRuleDomain::MachO, SecuritySeverity::Error,
     "Mach-O executables should enable MH_PIE and map an unmapped __PAGEZERO guard >= 4 KiB at virtual address 0.",
     "Link Mach-O executables with -Wl,-pie and preserve the default __PAGEZERO segment (avoid -pagezero_size 0)."},
    {"MACHO4002", "EnableMemoryProtectionAndWxorX", SecurityRuleDomain::MachO, SecuritySeverity::Error,
     "Mach-O images must enforce W^X segment/section protections (initprot and maxprot) and avoid executable stack or heap flags.",
     "Remove -allow_stack_execution, avoid RWX segment initial/maximum protections, and enable MH_NO_HEAP_EXECUTION on 32-bit targets."},
    {"MACHO4003", "EnableStackProtectorAndArcIndicators", SecurityRuleDomain::MachO, SecuritySeverity::Warning,
     "Native Mach-O code should emit stack-canary checks (___stack_chk_fail) and Objective-C binaries should use Automatic Reference Counting (ARC).",
     "Compile C/C++/ObjC code with -fstack-protector-strong and Objective-C targets with -fobjc-arc."},
    {"MACHO4004", "CodeSignatureAndHardenedRuntime", SecurityRuleDomain::MachO, SecuritySeverity::Warning,
     "Mach-O binaries should carry a structurally valid LC_CODE_SIGNATURE with Hardened Runtime (CS_RUNTIME); structural presence is distinct from cryptographic Apple trust.",
     "Sign Mach-O deliverables with codesign --options runtime using a valid Developer ID or platform identity and verify cryptographic trust on macOS."},
    {"MACHO4005", "SafeDylibRpathAndDyldHardening", SecurityRuleDomain::MachO, SecuritySeverity::Error,
     "Mach-O dylib install names and LC_RPATH entries must avoid relative, parent-traversal, or world-writable paths and preserve two-level namespace / dyld hardening.",
     "Use @executable_path, @loader_path, or @rpath without '..' or /tmp entries, keep MH_TWOLEVEL, and add -Wl,-sectcreate,__RESTRICT,__restrict,/dev/null for privileged binaries."},
    {"MACHO4006", "PointerAuthAndSegmentEncryption", SecurityRuleDomain::MachO, SecuritySeverity::Warning,
     "ARM64 Mach-O slices benefit from arm64e pointer authentication (PAC), and unencrypted segments (cryptid == 0) are required for complete static inspection.",
     "Build security-critical Apple Silicon targets for arm64e where supported, and decrypt FairPlay/encrypted slices (cryptid != 0) in an authorized environment before static audit."},

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
    if (static_cast<std::uint64_t>(lfanew) + 24u > static_cast<std::uint64_t>(raw_bytes.size())) {
        return std::nullopt;
    }
    const auto sig_off = static_cast<std::size_t>(lfanew);
    if (raw_bytes[sig_off] != 'P' || raw_bytes[sig_off + 1u] != 'E') {
        return std::nullopt;
    }
    return static_cast<std::uint64_t>(lfanew) + 24u;
}

#ifdef _WIN32
struct WinVerifyOutcome {
    LONG status{TRUST_E_NOSIGNATURE};
    bool host_verification_ran{false};
    bool signature_valid{false};
    bool publisher_trusted{false};
};

[[nodiscard]] WinVerifyOutcome verify_authenticode_offline_win32(
    std::span<const std::uint8_t> raw_bytes) {
    WinVerifyOutcome out{};
    if (raw_bytes.empty()) {
        return out;
    }

    auto staged = detail::ExclusiveTempFile::create("peelf_wvt_", ".bin", raw_bytes);
    if (!staged) {
        out.status = ERROR_WRITE_FAULT;
        return out;
    }

    const std::wstring wide_path = staged->path().wstring();
    WINTRUST_FILE_INFO file_info{};
    file_info.cbStruct = sizeof(file_info);
    file_info.pcwszFilePath = wide_path.c_str();
    file_info.hFile = nullptr;
    file_info.pgKnownSubject = nullptr;

    GUID action_guid = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    WINTRUST_DATA wvt{};
    wvt.cbStruct = sizeof(wvt);
    wvt.dwUIChoice = WTD_UI_NONE;
    wvt.fdwRevocationChecks = WTD_REVOKE_NONE;
    wvt.dwUnionChoice = WTD_CHOICE_FILE;
    wvt.pFile = &file_info;
    wvt.dwStateAction = WTD_STATEACTION_VERIFY;
    wvt.dwProvFlags = WTD_CACHE_ONLY_URL_RETRIEVAL | WTD_REVOCATION_CHECK_NONE;

    out.status = ::WinVerifyTrust(static_cast<HWND>(INVALID_HANDLE_VALUE), &action_guid, &wvt);
    out.host_verification_ran = true;
    wvt.dwStateAction = WTD_STATEACTION_CLOSE;
    (void)::WinVerifyTrust(static_cast<HWND>(INVALID_HANDLE_VALUE), &action_guid, &wvt);

    if (out.status == ERROR_SUCCESS) {
        out.signature_valid = true;
        out.publisher_trusted = true;
    } else if (out.status == static_cast<LONG>(CERT_E_UNTRUSTEDROOT) ||
               out.status == static_cast<LONG>(CERT_E_CHAINING) ||
               out.status == static_cast<LONG>(CERT_E_EXPIRED) ||
               out.status == static_cast<LONG>(TRUST_E_EXPLICIT_DISTRUST)) {
        out.signature_valid = true;
        out.publisher_trusted = false;
    }
    return out;
}
#endif

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
        (opt_off.has_value() && *opt_off + 0x48u <= raw_bytes.size())
            ? std::optional<std::uint64_t>(*opt_off + 0x46u)
            : std::nullopt;
    const std::optional<std::uint64_t> file_chars_off =
        (opt_off.has_value() && *opt_off >= 2u && *opt_off <= raw_bytes.size())
            ? std::optional<std::uint64_t>(*opt_off - 2u)
            : std::nullopt;
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

    // PE1001: ASLR (`DYNAMIC_BASE` without `IMAGE_FILE_RELOCS_STRIPPED` + `HIGH_ENTROPY_VA` on 64-bit)
    {
        SecurityFinding f;
        f.rule_id = "PE1001";
        f.rule_name = "EnableAddressSpaceLayoutRandomization";
        f.domain = SecurityRuleDomain::PE;
        f.subject = (dynamic_base && relocs_stripped) ? "FileHeader.Characteristics"
                                                      : "OptionalHeader.DllCharacteristics";
        f.virtual_address = base_va;
        f.file_offset = (dynamic_base && relocs_stripped) ? file_chars_off : dll_chars_off;
        f.remediation =
            "Link with /DYNAMICBASE (and /HIGHENTROPYVA on 64-bit targets) and avoid /FIXED or stripping .reloc.";

        if (!dynamic_base || relocs_stripped) {
            f.severity = SecuritySeverity::Error;
            f.summary = !dynamic_base
                            ? "ASLR is disabled (IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE is not set)."
                            : "IMAGE_FILE_RELOCS_STRIPPED is set, preventing runtime base relocation despite DYNAMIC_BASE.";
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
                "DllCharacteristics=0x{:04X} (DYNAMIC_BASE=1, HIGH_ENTROPY_VA=0), Characteristics=0x{:04X} (RELOCS_STRIPPED=0), ImageBase=0x{:X}, BaseRelocBlocks={}",
                dll_ch,
                file_ch,
                base_va,
                image.pe_base_relocations().size());
        } else {
            f.severity = SecuritySeverity::Pass;
            f.summary = image.is_64bit()
                            ? "ASLR and 64-bit High-Entropy VA are enabled."
                            : "ASLR (DYNAMIC_BASE) is enabled.";
            f.evidence = std::format(
                "DllCharacteristics=0x{:04X} (DYNAMIC_BASE=1{}{}), Characteristics=0x{:04X} (RELOCS_STRIPPED=0), BaseRelocBlocks={}",
                dll_ch,
                image.is_64bit() ? ", HIGH_ENTROPY_VA=1" : "",
                has_reloc_blocks ? ", .reloc present" : "",
                file_ch,
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
    // Separates (1) CertificateTable presence, (2) structural/cryptographic signature validity,
    // and (3) publisher trust chain verification.
    {
        const auto& certs = image.pe_certificates();
        std::uint32_t cert_dir_file_off = 0u;
        std::uint32_t cert_dir_size = 0u;
        for (const PeDataDirectory& dd : image.pe_data_directories()) {
            if (dd.index == 4u) { // Security / Certificate Table
                cert_dir_file_off = dd.rva;
                cert_dir_size = dd.size;
                break;
            }
        }

        SecurityFinding f;
        f.rule_id = "PE1005";
        f.rule_name = "SignBinaryWithAuthenticode";
        f.domain = SecurityRuleDomain::PE;
        f.subject = "CertificateTable";
        f.remediation = "Sign distributable PE binaries with Authenticode (signtool.exe) and enable /INTEGRITYCHECK when required.";

        const bool dir_claims_cert = (cert_dir_file_off != 0u || cert_dir_size != 0u);
        if (certs.empty() && dir_claims_cert) {
            f.severity = SecuritySeverity::Error;
            f.virtual_address = base_va;
            f.file_offset = cert_dir_file_off != 0u ? std::optional<std::uint64_t>(cert_dir_file_off) : dll_chars_off;
            f.summary = "Authenticode CertificateTable DataDirectory is non-empty, but the WIN_CERTIFICATE table is truncated or out of bounds.";
            f.evidence = std::format(
                "presence=corrupt_directory, signature_validity=invalid, publisher_trust=untrusted, CertDirFileOffset=0x{:X}, CertDirSize={}, ParsedCerts=0, FORCE_INTEGRITY={}",
                cert_dir_file_off,
                cert_dir_size,
                force_integrity ? 1 : 0);
        } else if (!certs.empty()) {
            f.file_offset = certs.front().file_offset;
            bool structure_valid = true;
            std::string struct_reason;
            for (std::size_t ci = 0u; ci < certs.size(); ++ci) {
                const PeCertificate& c = certs[ci];
                const bool valid_rev = (c.revision == 0x0200u || c.revision == 0x0100u);
                const bool valid_type = (c.certificate_type == 0x0002u); // WIN_CERT_TYPE_PKCS_SIGNED_DATA
                const bool valid_der_seq = (c.length >= 12u && c.certificate.size() >= 4u && c.certificate[0] == 0x30u);
                if (!valid_rev || !valid_type || !valid_der_seq) {
                    structure_valid = false;
                    struct_reason = std::format(
                        "Cert[{}]@file+0x{:X} malformed/unsupported (len={}, payload={}B, rev=0x{:04X}, type=0x{:04X}, tag=0x{:02X})",
                        ci,
                        c.file_offset,
                        c.length,
                        c.certificate.size(),
                        c.revision,
                        c.certificate_type,
                        c.certificate.empty() ? 0u : static_cast<unsigned>(c.certificate[0]));
                    break;
                }
            }

            if (!structure_valid) {
                f.severity = SecuritySeverity::Error;
                f.summary = "Embedded Authenticode WIN_CERTIFICATE entry is malformed or not PKCS#7 SignedData.";
                f.evidence = std::format(
                    "presence=present, signature_validity=corrupt_structure, publisher_trust=untrusted, {}, FORCE_INTEGRITY={}",
                    struct_reason,
                    force_integrity ? 1 : 0);
            } else {
#ifdef _WIN32
                const WinVerifyOutcome wvt = verify_authenticode_offline_win32(raw_bytes);
                if (!wvt.host_verification_ran) {
                    f.severity = SecuritySeverity::Note;
                    f.summary = std::format(
                        "Embedded Authenticode CertificateTable present ({} PKCS#7 entry/entries{}; raw file bytes unavailable for offline verification).",
                        certs.size(),
                        force_integrity ? ", FORCE_INTEGRITY=1" : "");
                    f.evidence = std::format(
                        "presence=present, signature_validity=unverified_host, publisher_trust=unverified_host, Cert[0]@file+0x{:X} (len={} bytes, rev=0x{:04X}, type=0x{:04X}), FORCE_INTEGRITY={}",
                        certs.front().file_offset,
                        certs.front().length,
                        certs.front().revision,
                        certs.front().certificate_type,
                        force_integrity ? 1 : 0);
                } else if (wvt.signature_valid && wvt.publisher_trusted) {
                    f.severity = SecuritySeverity::Pass;
                    f.summary = std::format(
                        "Authenticode signature and publisher trust verified ({} entry/entries{}).",
                        certs.size(),
                        force_integrity ? ", FORCE_INTEGRITY=1" : "");
                    f.evidence = std::format(
                        "presence=present, signature_validity=valid, publisher_trust=trusted, WinVerifyTrust=0x{:08X}, Cert[0]@file+0x{:X} (len={} bytes), FORCE_INTEGRITY={}",
                        static_cast<std::uint32_t>(wvt.status),
                        certs.front().file_offset,
                        certs.front().length,
                        force_integrity ? 1 : 0);
                } else if (wvt.signature_valid && !wvt.publisher_trusted) {
                    f.severity = SecuritySeverity::Warning;
                    f.summary = "Authenticode signature digest is intact, but the signing certificate chain is untrusted or expired.";
                    f.evidence = std::format(
                        "presence=present, signature_validity=valid, publisher_trust=untrusted_or_expired, WinVerifyTrust=0x{:08X}, Cert[0]@file+0x{:X} (len={} bytes), FORCE_INTEGRITY={}",
                        static_cast<std::uint32_t>(wvt.status),
                        certs.front().file_offset,
                        certs.front().length,
                        force_integrity ? 1 : 0);
                } else {
                    f.severity = SecuritySeverity::Error;
                    f.summary = "Embedded Authenticode CertificateTable failed cryptographic signature verification.";
                    f.evidence = std::format(
                        "presence=present, signature_validity=invalid, publisher_trust=untrusted, WinVerifyTrust=0x{:08X}, Cert[0]@file+0x{:X} (len={} bytes), FORCE_INTEGRITY={}",
                        static_cast<std::uint32_t>(wvt.status),
                        certs.front().file_offset,
                        certs.front().length,
                        force_integrity ? 1 : 0);
                }
#else
                f.severity = SecuritySeverity::Note;
                f.summary = std::format(
                    "Embedded Authenticode CertificateTable present ({} PKCS#7 entry/entries{}; cryptographic signature & publisher trust not verified on this host).",
                    certs.size(),
                    force_integrity ? ", FORCE_INTEGRITY=1" : "");
                f.evidence = std::format(
                    "presence=present, signature_validity=unverified_host, publisher_trust=unverified_host, Cert[0]@file+0x{:X} (len={} bytes, rev=0x{:04X}, type=0x{:04X}), FORCE_INTEGRITY={}",
                    certs.front().file_offset,
                    certs.front().length,
                    certs.front().revision,
                    certs.front().certificate_type,
                    force_integrity ? 1 : 0);
#endif
            }
        } else if (force_integrity) {
            f.severity = SecuritySeverity::Error;
            f.virtual_address = base_va;
            f.file_offset = dll_chars_off;
            f.summary = "FORCE_INTEGRITY (0x0080) is set, but no Authenticode CertificateTable is present.";
            f.evidence = std::format(
                "presence=absent, signature_validity=absent, publisher_trust=absent, DllCharacteristics=0x{:04X} (FORCE_INTEGRITY=1), Certificates=0",
                dll_ch);
        } else {
            f.severity = SecuritySeverity::Note;
            f.virtual_address = base_va;
            f.file_offset = dll_chars_off;
            f.summary = "Binary is unsigned (no Authenticode CertificateTable present).";
            f.evidence = std::format(
                "presence=absent, signature_validity=absent, publisher_trust=absent, Certificates=0, FORCE_INTEGRITY=0 (DllCharacteristics=0x{:04X})",
                dll_ch);
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
        } else if (dyn.tag == 15u) { // DT_RPATH (preserve empty "" for implicit CWD detection)
            rpaths.push_back(dyn.string_value);
        } else if (dyn.tag == 29u) { // DT_RUNPATH (preserve empty "" for implicit CWD detection)
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
            bool any_enabled_mitigation = false;
            std::vector<std::string> disabled_policies;
            for (const ProcessMitigationEntry& m : prof->mitigations) {
                if (m.enabled) {
                    any_enabled_mitigation = true;
                }
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
            const bool seccomp_observed = !prof->seccomp_mode.empty();
            const bool seccomp_disabled =
                seccomp_observed &&
                (prof->seccomp_mode == "0" || seccomp_low.starts_with("0 ") ||
                 seccomp_low.find("disabled") != std::string::npos);
            const bool seccomp_active = seccomp_observed && !seccomp_disabled;
            const bool no_new_privs_active = prof->no_new_privs.value_or(false);
            const bool has_affirmative_protection =
                any_enabled_mitigation || seccomp_active || no_new_privs_active;

            if (dep_or_aslr_disabled) {
                f.severity = SecuritySeverity::Error;
                f.summary = "Critical process runtime mitigation (DEP or ASLR) is disabled.";
            } else if (seccomp_disabled) {
                f.severity = SecuritySeverity::Warning;
                f.summary = "Process is running without a Seccomp syscall filter.";
            } else if (!has_affirmative_protection) {
                f.severity = SecuritySeverity::Note;
                f.summary = "Indeterminate: ProcessSecurityProfile contains no affirmative runtime mitigation or Seccomp telemetry.";
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
// Mach-O Security Audit Rules (`MACHO4001..MACHO4006`)
// ---------------------------------------------------------------------------

[[nodiscard]] bool is_macho_stack_canary_symbol(std::string_view raw_name) noexcept {
    while (!raw_name.empty() && raw_name.front() == '_') {
        raw_name.remove_prefix(1u);
    }
    if (const std::size_t at = raw_name.find('@'); at != std::string_view::npos) {
        raw_name = raw_name.substr(0u, at);
    }
    return raw_name == "stack_chk_fail" || raw_name == "stack_chk_guard";
}

[[nodiscard]] bool is_macho_objc_arc_symbol(std::string_view raw_name) noexcept {
    while (!raw_name.empty() && raw_name.front() == '_') {
        raw_name.remove_prefix(1u);
    }
    if (const std::size_t at = raw_name.find('@'); at != std::string_view::npos) {
        raw_name = raw_name.substr(0u, at);
    }
    return raw_name == "objc_release" ||
           raw_name == "objc_retain" ||
           raw_name == "objc_retainAutoreleasedReturnValue" ||
           raw_name == "objc_autoreleaseReturnValue" ||
           raw_name == "objc_storeStrong";
}

[[nodiscard]] std::string_view macho_audit_filetype_name(std::uint32_t ftype) noexcept {
    switch (ftype) {
        case macho::kMhObject:     return "MH_OBJECT";
        case macho::kMhExecute:    return "MH_EXECUTE";
        case macho::kMhFvmlib:     return "MH_FVMLIB";
        case macho::kMhCore:       return "MH_CORE";
        case macho::kMhPreload:    return "MH_PRELOAD";
        case macho::kMhDylib:      return "MH_DYLIB";
        case macho::kMhDylinker:   return "MH_DYLINKER";
        case macho::kMhBundle:     return "MH_BUNDLE";
        case macho::kMhDylibStub:  return "MH_DYLIB_STUB";
        case macho::kMhDsym:       return "MH_DSYM";
        case macho::kMhKextBundle: return "MH_KEXT_BUNDLE";
        case macho::kMhFileset:    return "MH_FILESET";
        default:                   return "MH_UNKNOWN";
    }
}

[[nodiscard]] std::string_view macho_audit_load_cmd_name(std::uint32_t cmd) noexcept {
    switch (cmd) {
        case macho::kLcIdDylib:         return "LC_ID_DYLIB";
        case macho::kLcLoadDylib:       return "LC_LOAD_DYLIB";
        case macho::kLcLoadWeakDylib:   return "LC_LOAD_WEAK_DYLIB";
        case macho::kLcReexportDylib:   return "LC_REEXPORT_DYLIB";
        case macho::kLcLazyLoadDylib:   return "LC_LAZY_LOAD_DYLIB";
        case macho::kLcLoadUpwardDylib: return "LC_LOAD_UPWARD_DYLIB";
        default:                        return "LC_LOAD_DYLIB";
    }
}

[[nodiscard]] bool is_macho_objc_metadata_section(const MachOSection& sec) noexcept {
    return sec.segment_name == "__OBJC" ||
           sec.section_name.starts_with("__objc_") ||
           sec.section_name == "__category_list" ||
           sec.section_name == "__class_list";
}

[[nodiscard]] bool has_unsafe_macho_path_traversal(std::string_view path) noexcept {
    std::size_t pos = 0u;
    while (pos <= path.size()) {
        const std::size_t slash = path.find('/', pos);
        const std::string_view comp = (slash == std::string_view::npos)
                                          ? path.substr(pos)
                                          : path.substr(pos, slash - pos);
        if (comp == ".." || comp == ".") {
            return true;
        }
        if (slash == std::string_view::npos) {
            break;
        }
        pos = slash + 1u;
    }
    return false;
}

[[nodiscard]] bool is_macho_world_writable_prefix(std::string_view path) noexcept {
    constexpr std::array<std::string_view, 5> kUnsafePrefixes = {
        "/tmp",
        "/var/tmp",
        "/private/tmp",
        "/private/var/tmp",
        "/dev/shm",
    };
    for (const std::string_view pfx : kUnsafePrefixes) {
        if (path == pfx) {
            return true;
        }
        if (path.size() > pfx.size() && path.starts_with(pfx) && path[pfx.size()] == '/') {
            return true;
        }
    }
    return false;
}

[[nodiscard]] bool is_macho_anchored_path(std::string_view path) noexcept {
    if (path.starts_with('/')) {
        return true;
    }
    constexpr std::array<std::string_view, 3> kLoaderTokens = {
        "@executable_path",
        "@loader_path",
        "@rpath",
    };
    for (const std::string_view tok : kLoaderTokens) {
        if (path == tok) {
            return true;
        }
        if (path.size() > tok.size() && path.starts_with(tok) && path[tok.size()] == '/') {
            return true;
        }
    }
    return false;
}

[[nodiscard]] bool is_standard_apple_bundle_sibling_path(std::string_view path) noexcept {
    // Standard macOS/iOS bundle binaries reside in `Foo.app/Contents/MacOS/Foo` (or
    // `Foo.framework/Versions/A/Helpers/Bar`) and reference sibling bundle directories via
    // `@executable_path/../Frameworks` or `@loader_path/../Frameworks`. Allow a single
    // leading `../<NonEmptySubdir>` ONLY when anchored at `@executable_path/` or `@loader_path/`
    // and when no remaining path component is `.` or `..` (preventing `../../` bundle escapes).
    std::string_view rest{};
    if (path.starts_with("@executable_path/../")) {
        rest = path.substr(std::string_view("@executable_path/../").size());
    } else if (path.starts_with("@loader_path/../")) {
        rest = path.substr(std::string_view("@loader_path/../").size());
    } else {
        return false;
    }
    while (!rest.empty() && rest.back() == '/') {
        rest.remove_suffix(1u);
    }
    if (rest.empty()) {
        return false;
    }
    return !has_unsafe_macho_path_traversal(rest);
}

[[nodiscard]] std::optional<std::string> classify_unsafe_macho_loader_path(
    std::string_view path,
    bool is_rpath) {
    if (path.empty()) {
        return is_rpath ? std::string("empty LC_RPATH entry")
                        : std::string("empty dylib install name");
    }
    if (!is_macho_anchored_path(path)) {
        return std::format("unanchored relative path '{}'", path);
    }
    if (has_unsafe_macho_path_traversal(path) && !is_standard_apple_bundle_sibling_path(path)) {
        return std::format("relative '.' or '..' traversal segment in '{}'", path);
    }
    if (is_macho_world_writable_prefix(path)) {
        return std::format("world-writable directory prefix in '{}'", path);
    }
    return std::nullopt;
}

void evaluate_macho_rules(
    const IBinaryImage& image,
    SecurityAuditReport& report) {
    const MachOHeader* mh = image.macho_header();
    if (mh == nullptr) {
        report.status = SubsystemStatus::unavailable("security_audit", "Mach-O header unavailable");
        return;
    }

    const std::uint64_t hdr_off = image.container_slice_offset();
    const std::uint64_t base_va = image.image_base();

    // MACHO4001: EnablePieAndZeroPage
    {
        SecurityFinding f;
        f.rule_id = "MACHO4001";
        f.rule_name = "EnablePieAndZeroPage";
        f.domain = SecurityRuleDomain::MachO;
        f.subject = "mach_header.flags / __PAGEZERO";
        f.virtual_address = base_va;
        f.file_offset = hdr_off;
        f.remediation = "Link Mach-O executables with -Wl,-pie and preserve the default __PAGEZERO segment (avoid -pagezero_size 0).";

        const MachOSegmentCommand* pagezero = nullptr;
        for (const MachOSegmentCommand& seg : image.macho_segments()) {
            if (seg.is_pagezero()) {
                pagezero = &seg;
                break;
            }
        }

        if (mh->file_type == macho::kMhExecute) {
            const bool has_pie = mh->has_pie();
            const bool valid_pz = (pagezero != nullptr) &&
                                  (pagezero->virtual_address == 0u) &&
                                  (pagezero->virtual_size >= 4096u) &&
                                  (pagezero->initprot == 0u) &&
                                  (pagezero->maxprot == 0u);
            if (!has_pie || !valid_pz) {
                f.severity = SecuritySeverity::Error;
                std::vector<std::string> issues;
                if (!has_pie) {
                    issues.emplace_back("MH_PIE (0x200000) is not set");
                }
                if (pagezero == nullptr) {
                    issues.emplace_back("__PAGEZERO segment is missing");
                } else {
                    if (pagezero->virtual_address != 0u) {
                        issues.push_back(std::format("__PAGEZERO vmaddr=0x{:X} (expected 0)", pagezero->virtual_address));
                    }
                    if (pagezero->virtual_size < 4096u) {
                        issues.push_back(std::format("__PAGEZERO vmsize=0x{:X} (< 4096 bytes)", pagezero->virtual_size));
                    }
                    if (pagezero->initprot != 0u || pagezero->maxprot != 0u) {
                        issues.push_back(std::format(
                            "__PAGEZERO has non-zero protections (initprot=0x{:X}, maxprot=0x{:X})",
                            pagezero->initprot,
                            pagezero->maxprot));
                    }
                }
                std::string joined;
                for (std::size_t i = 0u; i < issues.size(); ++i) {
                    if (i > 0u) {
                        joined += "; ";
                    }
                    joined += issues[i];
                }
                f.summary = "Mach-O executable lacks full ASLR (MH_PIE) or a valid unmapped __PAGEZERO guard segment.";
                f.evidence = std::format(
                    "filetype=MH_EXECUTE, flags=0x{:08X}, MH_PIE={}, issues=[{}]",
                    mh->flags,
                    has_pie ? 1 : 0,
                    joined);
            } else {
                f.severity = SecuritySeverity::Pass;
                f.summary = "MH_EXECUTE enables MH_PIE and maps an unmapped __PAGEZERO guard page at VA 0.";
                f.evidence = std::format(
                    "filetype=MH_EXECUTE, flags=0x{:08X} (MH_PIE=1), __PAGEZERO=[0x0, 0x{:X}), initprot=0, maxprot=0",
                    mh->flags,
                    pagezero->virtual_size);
            }
        } else if (mh->file_type == macho::kMhObject || mh->file_type == macho::kMhDsym) {
            f.severity = SecuritySeverity::Note;
            f.summary = "Non-linked Mach-O object/dSYM container; MH_PIE and __PAGEZERO apply at final executable link.";
            f.evidence = std::format("filetype={} (0x{:X}), flags=0x{:08X}",
                                     macho_audit_filetype_name(mh->file_type),
                                     mh->file_type,
                                     mh->flags);
        } else {
            f.severity = SecuritySeverity::Pass;
            f.summary = std::format("{} image is inherently position-independent.",
                                    macho_audit_filetype_name(mh->file_type));
            f.evidence = std::format("filetype={} (0x{:X}), flags=0x{:08X}",
                                     macho_audit_filetype_name(mh->file_type),
                                     mh->file_type,
                                     mh->flags);
        }
        tally_finding(report, std::move(f));
    }

    // MACHO4002: EnableMemoryProtectionAndWxorX
    {
        SecurityFinding f;
        f.rule_id = "MACHO4002";
        f.rule_name = "EnableMemoryProtectionAndWxorX";
        f.domain = SecurityRuleDomain::MachO;
        f.subject = "Segments / Sections / Stack & Heap NX";
        f.virtual_address = base_va;
        f.file_offset = hdr_off;
        f.remediation = "Remove -allow_stack_execution, avoid RWX segment initial/maximum protections, and enable MH_NO_HEAP_EXECUTION on 32-bit targets.";

        const bool exec_stack = mh->allows_stack_execution();
        const bool needs_explicit_heap_nx = (!mh->is_64bit && mh->file_type == macho::kMhExecute);
        const bool missing_32bit_heap_nx = needs_explicit_heap_nx && !mh->has_no_heap_execution();

        std::vector<std::string> hard_errors;
        if (exec_stack) {
            hard_errors.emplace_back("MH_ALLOW_STACK_EXECUTION (0x00020000) is set");
        }

        for (const MachOSegmentCommand& seg : image.macho_segments()) {
            const bool init_wx = seg.init_is_wx();
            const bool max_wx = seg.max_is_wx();
            if (init_wx || max_wx) {
                if (f.file_offset == hdr_off && seg.file_offset != 0u) {
                    f.file_offset = seg.file_offset;
                    f.virtual_address = seg.virtual_address;
                }
                hard_errors.push_back(std::format(
                    "segment '{}' [0x{:X}, 0x{:X}) violates W^X (initprot=0x{:X}, maxprot=0x{:X})",
                    seg.name.empty() ? "<unnamed>" : seg.name,
                    seg.virtual_address,
                    seg.virtual_address + seg.virtual_size,
                    seg.initprot,
                    seg.maxprot));
            }
        }

        for (const MachOSection& sec : image.macho_sections()) {
            if (sec.writable && sec.executable) {
                hard_errors.push_back(std::format(
                    "section '{},{}' @ 0x{:X} combines write and execute permissions",
                    sec.segment_name,
                    sec.section_name,
                    sec.virtual_address));
            }
        }

        if (!hard_errors.empty()) {
            f.severity = SecuritySeverity::Error;
            std::string joined;
            for (std::size_t i = 0u; i < hard_errors.size(); ++i) {
                if (i > 0u) {
                    joined += "; ";
                }
                joined += hard_errors[i];
            }
            f.summary = "Mach-O image permits executable stack or writable+executable (RWX) memory mappings.";
            f.evidence = std::format(
                "flags=0x{:08X}, MH_ALLOW_STACK_EXECUTION={}, MH_NO_HEAP_EXECUTION={}, violations=[{}]",
                mh->flags,
                exec_stack ? 1 : 0,
                mh->has_no_heap_execution() ? 1 : 0,
                joined);
        } else if (missing_32bit_heap_nx) {
            f.severity = SecuritySeverity::Warning;
            f.summary = "32-bit Mach-O executable does not set MH_NO_HEAP_EXECUTION.";
            f.evidence = std::format(
                "bits=32, filetype=MH_EXECUTE, flags=0x{:08X} (MH_NO_HEAP_EXECUTION=0, RWX_segments=0)",
                mh->flags);
        } else {
            f.severity = SecuritySeverity::Pass;
            f.summary = "Mach-O segments/sections enforce W^X (initprot & maxprot) with non-executable stack/heap posture.";
            f.evidence = std::format(
                "bits={}, flags=0x{:08X}, MH_ALLOW_STACK_EXECUTION=0, MH_NO_HEAP_EXECUTION={}, segments={}, RWX=0",
                mh->is_64bit ? 64 : 32,
                mh->flags,
                mh->has_no_heap_execution() ? 1 : 0,
                image.macho_segments().size());
        }
        tally_finding(report, std::move(f));
    }

    // MACHO4003: EnableStackProtectorAndArcIndicators
    {
        SecurityFinding f;
        f.rule_id = "MACHO4003";
        f.rule_name = "EnableStackProtectorAndArcIndicators";
        f.domain = SecurityRuleDomain::MachO;
        f.subject = "SymbolTable / Imports / ObjC Metadata";
        f.virtual_address = base_va;
        f.file_offset = hdr_off;
        f.remediation = "Compile C/C++/ObjC code with -fstack-protector-strong and Objective-C targets with -fobjc-arc.";

        bool has_canary = false;
        std::string canary_sym;
        bool has_arc = false;
        std::string arc_sym;

        for (const ImportEntry& imp : image.imports()) {
            if (!has_canary && is_macho_stack_canary_symbol(imp.name)) {
                has_canary = true;
                canary_sym = imp.name;
            }
            if (!has_arc && is_macho_objc_arc_symbol(imp.name)) {
                has_arc = true;
                arc_sym = imp.name;
            }
        }
        for (const Symbol& sym : image.symbols()) {
            if (!has_canary && is_macho_stack_canary_symbol(sym.name)) {
                has_canary = true;
                canary_sym = sym.name;
            }
            if (!has_arc && is_macho_objc_arc_symbol(sym.name)) {
                has_arc = true;
                arc_sym = sym.name;
            }
        }

        bool has_objc_metadata = false;
        std::string first_objc_section;
        for (const MachOSection& sec : image.macho_sections()) {
            if (is_macho_objc_metadata_section(sec)) {
                has_objc_metadata = true;
                if (first_objc_section.empty()) {
                    first_objc_section = std::format("{},{}", sec.segment_name, sec.section_name);
                }
            }
        }

        const bool symbols_stripped = image.symbols().empty() && image.imports().empty();
        if (symbols_stripped) {
            f.severity = SecuritySeverity::Note;
            f.summary = "Symbol and import tables are empty or stripped; stack-canary and ObjC ARC indicators cannot be verified statically.";
            f.evidence = std::format(
                "symbols=0, imports=0, objc_metadata={}",
                has_objc_metadata ? first_objc_section : "absent");
        } else if (has_canary && (!has_objc_metadata || has_arc)) {
            f.severity = SecuritySeverity::Pass;
            f.summary = has_objc_metadata
                            ? "Stack-canary check and Objective-C ARC symbols are present."
                            : "Stack-canary check symbol is present (no Objective-C metadata sections detected).";
            f.evidence = std::format(
                "stack_canary='{}', objc_metadata={}, objc_arc={}",
                canary_sym,
                has_objc_metadata ? first_objc_section : "absent",
                has_arc ? arc_sym : "n/a");
        } else {
            f.severity = SecuritySeverity::Warning;
            std::vector<std::string> gaps;
            if (!has_canary) {
                gaps.emplace_back("missing ___stack_chk_fail / ___stack_chk_guard");
            }
            if (has_objc_metadata && !has_arc) {
                gaps.push_back(std::format(
                    "Objective-C metadata ({}) present without _objc_release / ARC runtime symbols",
                    first_objc_section));
            }
            std::string joined;
            for (std::size_t i = 0u; i < gaps.size(); ++i) {
                if (i > 0u) {
                    joined += "; ";
                }
                joined += gaps[i];
            }
            f.summary = std::format("Mach-O hardening indicator gap: {}.", joined);
            f.evidence = std::format(
                "stack_canary={}, objc_metadata={}, objc_arc={}, symbols={}, imports={}",
                has_canary ? canary_sym : "absent",
                has_objc_metadata ? first_objc_section : "absent",
                has_arc ? arc_sym : "absent",
                image.symbols().size(),
                image.imports().size());
        }
        tally_finding(report, std::move(f));
    }

    // MACHO4004: CodeSignatureAndHardenedRuntime
    // Strictly separates structural LC_CODE_SIGNATURE presence from cryptographic trust!
    {
        SecurityFinding f;
        f.rule_id = "MACHO4004";
        f.rule_name = "CodeSignatureAndHardenedRuntime";
        f.domain = SecurityRuleDomain::MachO;
        f.subject = "LC_CODE_SIGNATURE";
        f.virtual_address = base_va;
        f.file_offset = hdr_off;
        f.remediation = "Sign Mach-O deliverables with codesign --options runtime using a valid Developer ID or platform identity and verify cryptographic trust on macOS.";

        const MachOCodeSignatureInfo* cs = image.macho_code_signature();
        if (cs == nullptr || !cs->present) {
            if (mh->file_type == macho::kMhObject || mh->file_type == macho::kMhDsym) {
                f.severity = SecuritySeverity::Note;
                f.summary = "Non-executable Mach-O object/dSYM container has no LC_CODE_SIGNATURE.";
            } else {
                f.severity = SecuritySeverity::Warning;
                f.summary = "Mach-O binary is unsigned (no LC_CODE_SIGNATURE load command present).";
            }
            f.evidence = std::format(
                "lc_code_signature=absent, cryptographically_verified=false, trust_provenance=absent, filetype={}",
                macho_audit_filetype_name(mh->file_type));
        } else {
            f.file_offset = cs->container_offset != 0u ? cs->container_offset : hdr_off;
            if (!cs->superblob_valid || !cs->has_code_directory) {
                f.severity = SecuritySeverity::Error;
                f.summary = "LC_CODE_SIGNATURE payload is truncated, malformed, or missing a CodeDirectory blob.";
                f.evidence = std::format(
                    "lc_code_signature=corrupt_structure, superblob_valid={}, has_code_directory={}, dataoff=0x{:X}, datasize={}, cryptographically_verified=false",
                    cs->superblob_valid ? 1 : 0,
                    cs->has_code_directory ? 1 : 0,
                    cs->slice_offset,
                    cs->data_size);
            } else {
                const bool adhoc = cs->is_adhoc();
                const bool runtime = cs->has_hardened_runtime();
                const bool cms_nonempty = cs->has_nonempty_cms_signature;
                const bool needs_runtime = (mh->file_type == macho::kMhExecute);

                if ((needs_runtime && !runtime) || adhoc || !cms_nonempty) {
                    f.severity = SecuritySeverity::Warning;
                    std::vector<std::string> reasons;
                    if (adhoc) {
                        reasons.emplace_back("ad-hoc signature (CS_ADHOC) lacks publisher certificate identity");
                    }
                    if (needs_runtime && !runtime) {
                        reasons.emplace_back("Hardened Runtime (CS_RUNTIME) is not enabled");
                    }
                    if (!adhoc && !cms_nonempty) {
                        reasons.emplace_back("CMS signature blob is empty");
                    }
                    std::string joined;
                    for (std::size_t i = 0u; i < reasons.size(); ++i) {
                        if (i > 0u) {
                            joined += "; ";
                        }
                        joined += reasons[i];
                    }
                    f.summary = std::format(
                        "LC_CODE_SIGNATURE structurally present ({}); cryptographic Apple signature/notarization trust is unverified offline.",
                        joined);
                } else if (cs->cryptographically_verified) {
                    f.severity = SecuritySeverity::Pass;
                    f.summary = "LC_CODE_SIGNATURE verified with Hardened Runtime (CS_RUNTIME) and trusted cryptographic signature.";
                } else {
                    f.severity = SecuritySeverity::Note;
                    f.summary =
                        "Structurally valid LC_CODE_SIGNATURE with Hardened Runtime (CS_RUNTIME) and CMS blob present; "
                        "cryptographic Apple signature/notarization trust is unverified (not checked in offline/cross-OS static analysis).";
                }
                f.evidence = std::format(
                    "lc_code_signature=present_structural, cs_flags=0x{:08X}, cs_adhoc={}, cs_runtime={}, cms_blob={}, identifier='{}', team_id='{}', cryptographically_verified={}, trust_provenance={}",
                    cs->cd_flags,
                    adhoc ? 1 : 0,
                    runtime ? 1 : 0,
                    cms_nonempty ? "nonempty" : (cs->has_cms_blob ? "empty" : "absent"),
                    cs->identifier.empty() ? "<none>" : cs->identifier,
                    cs->team_id.empty() ? "<none>" : cs->team_id,
                    cs->cryptographically_verified ? "true" : "false",
                    cs->cryptographically_verified ? "os_verified" : "unverified_offline_structural_only");
            }
        }
        tally_finding(report, std::move(f));
    }

    // MACHO4005: SafeDylibRpathAndDyldHardening
    {
        SecurityFinding f;
        f.rule_id = "MACHO4005";
        f.rule_name = "SafeDylibRpathAndDyldHardening";
        f.domain = SecurityRuleDomain::MachO;
        f.subject = "LC_RPATH / LC_LOAD_*_DYLIB / Dyld Namespace";
        f.virtual_address = base_va;
        f.file_offset = hdr_off;
        f.remediation = "Use @executable_path, @loader_path, or @rpath without '..' or /tmp entries, keep MH_TWOLEVEL, and add -Wl,-sectcreate,__RESTRICT,__restrict,/dev/null for privileged binaries.";

        std::vector<std::string> path_errors;
        for (const MachORpathEntry& rp : image.macho_rpaths()) {
            if (const auto bad = classify_unsafe_macho_loader_path(rp.path, true); bad.has_value()) {
                if (f.file_offset == hdr_off && rp.container_offset != 0u) {
                    f.file_offset = rp.container_offset;
                }
                path_errors.push_back(std::format("LC_RPATH: {}", *bad));
            }
        }
        for (const MachODylibDependency& dy : image.macho_dylibs()) {
            if (dy.ordinal == 0u && mh->file_type != macho::kMhDylib) {
                continue;
            }
            if (const auto bad = classify_unsafe_macho_loader_path(dy.name, false); bad.has_value()) {
                path_errors.push_back(std::format("{}: {}", macho_audit_load_cmd_name(dy.cmd), *bad));
            }
        }

        bool has_restrict = false;
        for (const MachOSegmentCommand& seg : image.macho_segments()) {
            if (seg.name == "__RESTRICT") {
                has_restrict = true;
                break;
            }
        }
        if (!has_restrict) {
            for (const MachOSection& sec : image.macho_sections()) {
                if (sec.segment_name == "__RESTRICT" && sec.section_name == "__restrict") {
                    has_restrict = true;
                    break;
                }
            }
        }
        const MachOCodeSignatureInfo* cs = image.macho_code_signature();
        const bool cs_restrict = (cs != nullptr && cs->has_code_directory && (cs->cd_flags & macho::kCsRestrict) != 0u);

        const bool dynamic_img = ((mh->flags & macho::kMhDyldLink) != 0u) || !image.macho_dylibs().empty();
        const bool forces_flat = (mh->flags & macho::kMhForceFlat) != 0u;
        const bool flat_ns = forces_flat ||
                             (dynamic_img && mh->file_type != macho::kMhObject && !mh->has_twolevel_namespace());

        if (!path_errors.empty()) {
            f.severity = SecuritySeverity::Error;
            std::string joined;
            for (std::size_t i = 0u; i < path_errors.size(); ++i) {
                if (i > 0u) {
                    joined += "; ";
                }
                joined += path_errors[i];
            }
            f.summary = "Mach-O image contains unsafe LC_RPATH or dylib install-name paths susceptible to dylib hijacking.";
            f.evidence = std::format(
                "rpaths={}, dylibs={}, MH_TWOLEVEL={}, MH_FORCE_FLAT={}, restrict={}, unsafe=[{}]",
                image.macho_rpaths().size(),
                image.macho_dylibs().size(),
                mh->has_twolevel_namespace() ? 1 : 0,
                forces_flat ? 1 : 0,
                (has_restrict || cs_restrict) ? 1 : 0,
                joined);
        } else if (flat_ns) {
            f.severity = SecuritySeverity::Warning;
            f.summary = "Mach-O dynamic image uses flat symbol namespace (missing MH_TWOLEVEL or sets MH_FORCE_FLAT).";
            f.evidence = std::format(
                "flags=0x{:08X}, MH_TWOLEVEL={}, MH_FORCE_FLAT={}, restrict={}",
                mh->flags,
                mh->has_twolevel_namespace() ? 1 : 0,
                forces_flat ? 1 : 0,
                (has_restrict || cs_restrict) ? 1 : 0);
        } else {
            f.severity = SecuritySeverity::Pass;
            f.summary = "Mach-O dylib install names and LC_RPATH entries use safe anchored paths with two-level namespace isolation.";
            f.evidence = std::format(
                "rpaths={}, dylibs={}, MH_TWOLEVEL={}, __RESTRICT={}, CS_RESTRICT={}",
                image.macho_rpaths().size(),
                image.macho_dylibs().size(),
                mh->has_twolevel_namespace() ? 1 : 0,
                has_restrict ? 1 : 0,
                cs_restrict ? 1 : 0);
        }
        tally_finding(report, std::move(f));
    }

    // MACHO4006: PointerAuthAndSegmentEncryption
    {
        SecurityFinding f;
        f.rule_id = "MACHO4006";
        f.rule_name = "PointerAuthAndSegmentEncryption";
        f.domain = SecurityRuleDomain::MachO;
        f.subject = "CPU Subtype (PAC) / LC_ENCRYPTION_INFO";
        f.virtual_address = base_va;
        f.file_offset = hdr_off;
        f.remediation = "Build security-critical Apple Silicon targets for arm64e where supported, and decrypt FairPlay/encrypted slices (cryptid != 0) in an authorized environment before static audit.";

        const MachOEncryptionInfo* enc = image.macho_encryption_info();
        const bool encrypted = (enc != nullptr && enc->is_encrypted());
        if (encrypted) {
            f.severity = SecuritySeverity::Warning;
            if (enc->container_cryptoff != 0u) {
                f.file_offset = enc->container_cryptoff;
            }
            f.summary = "Mach-O LC_ENCRYPTION_INFO payload is encrypted (cryptid != 0); static disassembly, strings, and symbol analysis are degraded.";
            f.evidence = std::format(
                "cryptid={}, cryptoff=0x{:X}, cryptsize=0x{:X}, arch={}, arm64e={}",
                enc->cryptid,
                enc->cryptoff,
                enc->cryptsize,
                to_string(image.architecture()),
                mh->is_arm64e ? 1 : 0);
        } else if (image.architecture() == Architecture::ARM64) {
            if (mh->is_arm64e) {
                f.severity = SecuritySeverity::Pass;
                f.summary = "ARM64 Mach-O slice enables arm64e pointer authentication (PAC) and has unencrypted segments (cryptid == 0).";
                f.evidence = std::format(
                    "arch=ARM64, arm64e=1, ptrauth_abi={}, ptrauth_version={}, cryptid=0",
                    mh->ptrauth_abi,
                    mh->ptrauth_version);
            } else {
                f.severity = SecuritySeverity::Note;
                f.summary = "ARM64 Mach-O slice uses baseline arm64 ABI without arm64e pointer authentication (PAC); payload is unencrypted (cryptid == 0).";
                f.evidence = std::format(
                    "arch=ARM64, arm64e=0, cpu_subtype=0x{:08X}, cryptid=0",
                    mh->cpu_subtype);
            }
        } else {
            f.severity = SecuritySeverity::Pass;
            f.summary = "Mach-O slice is unencrypted (cryptid == 0); arm64e PAC is not applicable to this architecture.";
            f.evidence = std::format(
                "arch={}, cpu_type=0x{:08X}, cryptid=0",
                to_string(image.architecture()),
                mh->cpu_type);
        }
        tally_finding(report, std::move(f));
    }

    report.status = SubsystemStatus::available(
        "security_audit",
        std::format("Evaluated 6 Mach-O security rules: {} error(s), {} warning(s), {} note(s), {} pass",
                    report.error_count,
                    report.warning_count,
                    report.note_count,
                    report.pass_count));
}

// ---------------------------------------------------------------------------
// JSON Escaping & Atomic File Write Helpers
// ---------------------------------------------------------------------------

[[nodiscard]] Result<BinaryOpenOptions> build_headless_open_options(
    const std::optional<std::string>& slice_selector) {
    BinaryOpenOptions open_opts{};
    if (!slice_selector.has_value()) {
        return open_opts;
    }
    const std::string_view sel = *slice_selector;
    if (sel.empty()) {
        return make_error("--slice selector must not be empty");
    }
    bool all_digits = true;
    for (const char ch : sel) {
        if (ch < '0' || ch > '9') {
            all_digits = false;
            break;
        }
    }
    if (all_digits) {
        std::size_t idx = 0u;
        const auto [ptr, ec] = std::from_chars(sel.data(), sel.data() + sel.size(), idx);
        if (ec != std::errc{} || ptr != sel.data() + sel.size()) {
            return make_error(std::format("Invalid numeric --slice index '{}'", sel));
        }
        open_opts.selected_slice_index = idx;
    } else {
        open_opts.preferred_arch_name = std::string(sel);
    }
    return open_opts;
}

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
    return detail::write_text_atomically(output_path, content, true, true);
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
    } else if (image.format() == Format::MachO) {
        evaluate_macho_rules(image, report);
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

    SignatureRuleSet active_rules{};
    if (options.include_builtin_rules) {
        SignatureRuleSet builtin = builtin_signature_rules();
        active_rules.rules.insert(active_rules.rules.end(),
                                  std::make_move_iterator(builtin.rules.begin()),
                                  std::make_move_iterator(builtin.rules.end()));
    }
    for (const std::filesystem::path& rule_path : options.rule_paths) {
        auto loaded = load_signature_rules_file(rule_path);
        if (!loaded.has_value()) {
            return std::unexpected(loaded.error());
        }
        if (!loaded->ok()) {
            const SignatureRuleDiagnostic& diag = loaded->diagnostics.front();
            return make_error(std::format("Rule syntax error in {}:{}:{}: {}",
                                          diag.source_name,
                                          diag.line,
                                          diag.column,
                                          diag.message));
        }
        active_rules.rules.insert(active_rules.rules.end(),
                                  std::make_move_iterator(loaded->ruleset.rules.begin()),
                                  std::make_move_iterator(loaded->ruleset.rules.end()));
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

    HeadlessAnalysisReport report;
    report.binary_path = options.binary_path;
    report.sha256 = sha256_hex(raw_bytes);
    report.file_size = raw_bytes.size();

    // Crash dump support (`WU-14`): Windows `"MDMP"` .dmp and Linux ELF `ET_CORE`
    // must be checked before `parse_image`, since `ET_CORE` starts with `\x7FELF`.
    if (is_crash_dump_bytes(raw_bytes)) {
        auto opened = open_crash_dump_bytes(std::move(raw_bytes), options.binary_path);
        if (!opened.has_value()) {
            return std::unexpected(opened.error());
        }
        report.crash_dump = std::move(*opened);

        // Opportunistically hydrate the faulting or main module image when mapped/backed.
        const auto regs = report.crash_dump->memory_regions();
        const auto mods = report.crash_dump->modules();
        if (regs.has_value() && mods.has_value() && !mods->empty()) {
            std::size_t chosen_idx = 0u;
            const auto& csum = report.crash_dump->crash_summary();
            const std::uint64_t fault_ip =
                (csum.exception.has_value() && csum.exception->instruction_pointer.has_value())
                    ? *csum.exception->instruction_pointer
                    : 0u;
            bool matched = false;
            if (fault_ip != 0u) {
                for (std::size_t i = 0u; i < mods->size(); ++i) {
                    if (fault_ip >= (*mods)[i].base_address &&
                        fault_ip < (*mods)[i].base_address + std::max<std::uint64_t>((*mods)[i].size, 1u)) {
                        chosen_idx = i;
                        matched = true;
                        break;
                    }
                }
            }
            if (!matched) {
                for (std::size_t i = 0u; i < mods->size(); ++i) {
                    if ((*mods)[i].is_main_module) {
                        chosen_idx = i;
                        break;
                    }
                }
            }
            if (auto loaded_mod = load_live_module_image(*report.crash_dump, (*mods)[chosen_idx], *regs)) {
                report.image = std::move(*loaded_mod);
            }
        }

        const ProcessInternalsSnapshot internals = report.crash_dump->crash_internals();
        const ProcessSecurityProfile* sec_ptr =
            internals.security.has_value() ? &(*internals.security.value) : nullptr;
        if (report.image != nullptr) {
            DependencyResolveOptions dep_opts;
            dep_opts.root_path = options.binary_path;
            dep_opts.search_roots = options.search_roots;
            report.dependencies = build_dependency_graph(*report.image, dep_opts);
            report.security = audit_security(*report.image, {}, report.crash_dump.get(), sec_ptr);
        } else {
            report.security = audit_live_process_security(*report.crash_dump, sec_ptr);
        }

        report.primary_provenance = ProvenanceTag::CrashDump;
        report.target_profile = derive_target_profile(
            report.image.get(),
            report.crash_dump.get(),
            false,
            false);
        report.capabilities = capabilities_for(
            report.target_profile,
            ProviderFacts::detect_host_providers());
        {
            TargetInstanceId tid;
            tid.backend = report.target_profile.backend;
            tid.pid = report.crash_dump->pid();
            tid.image_sha256 = report.sha256;
            if (report.image != nullptr) {
                const BackingImageIdentity bid = extract_backing_image_identity(
                    *report.image);
                tid.build_id_or_pdb_guid = bid.primary_identifier();
            }
            report.analysis_stamp = CaptureStamp::capture_now(
                tid,
                1u,
                true,
                CaptureAvailability::Complete);
        }

        if (report.image != nullptr) {
            report.executable_settings = extract_executable_settings(
                *report.image,
                {},
                report.analysis_stamp);
            report.executable_settings.target_profile = report.target_profile;
        } else {
            CaptureStamp unavail_stamp = report.analysis_stamp;
            unavail_stamp.availability = CaptureAvailability::Unavailable;
            report.executable_settings.target_profile = report.target_profile;
            report.executable_settings.declared_in_file =
                Observed<DeclaredSettings>::unavailable(
                    ProvenanceTag::CrashDump,
                    "No hydrated PE/ELF module image available in crash dump",
                    unavail_stamp);
            report.executable_settings.launch_environment =
                Observed<LaunchEnvironmentSettings>::unavailable(
                    ProvenanceTag::CrashDump,
                    "Crash dump launch environment hydration requires runtime settings capture",
                    unavail_stamp);
            report.executable_settings.observed_runtime =
                Observed<ObservedRuntimeConfiguration>::unavailable(
                    ProvenanceTag::CrashDump,
                    "Crash dump runtime configuration hydration requires runtime settings capture",
                    unavail_stamp);
        }

        if (options.compare_path.has_value()) {
            return make_error("--compare is not supported when the primary input is a crash dump");
        }
        report.crypto_hits = scan_crypto_and_packer_constants(*report.crash_dump);
        if (!active_rules.rules.empty()) {
            report.rule_matches = evaluate_signature_rules(active_rules, *report.crash_dump);
        }
        return report;
    }

    auto open_opts = build_headless_open_options(options.slice_selector);
    if (!open_opts.has_value()) {
        return std::unexpected(open_opts.error());
    }

    if (auto cinfo = inspect_binary_container(raw_bytes); cinfo.has_value()) {
        report.container_info = std::move(*cinfo);
    }

    auto parsed = open_binary_image(raw_bytes, *open_opts);
    if (!parsed.has_value()) {
        return make_error(std::format("Failed to parse '{}': {}",
                                      options.binary_path.string(),
                                      parsed.error().message));
    }

    report.image = std::move(*parsed);
    report.selected_slice_index = report.image->container_slice_index();
    if (report.selected_slice_index < report.container_info.slices.size()) {
        report.selected_slice_arch =
            report.container_info.slices[report.selected_slice_index].arch_name;
    } else {
        report.selected_slice_arch = std::string(to_string(report.image->architecture()));
    }
    report.primary_provenance = ProvenanceTag::DiskFile;
    report.target_profile = derive_target_profile(
        report.image.get(),
        nullptr,
        false,
        false);
    report.capabilities = capabilities_for(
        report.target_profile,
        ProviderFacts::detect_host_providers());
    {
        const BackingImageIdentity bid = extract_backing_image_identity(
            *report.image,
            raw_bytes);
        TargetInstanceId tid;
        tid.backend = BackendKind::StaticFile;
        tid.image_sha256 = report.sha256;
        tid.build_id_or_pdb_guid = bid.primary_identifier();
        report.analysis_stamp = CaptureStamp::capture_now(
            tid,
            1u,
            true,
            CaptureAvailability::Complete);
    }

    DependencyResolveOptions dep_opts;
    dep_opts.root_path = options.binary_path;
    dep_opts.search_roots = options.search_roots;
    report.dependencies = build_dependency_graph(*report.image, dep_opts);

    report.security = audit_security(*report.image, raw_bytes);
    report.executable_settings = extract_executable_settings(
        *report.image,
        raw_bytes,
        report.analysis_stamp);
    report.executable_settings.target_profile = report.target_profile;

    if (report.image->format() == Format::PE) {
        report.pe_rich_header = parse_pe_rich_header(raw_bytes);
    }
    report.crypto_hits = scan_crypto_and_packer_constants(raw_bytes, report.image.get());
    if (!active_rules.rules.empty()) {
        report.rule_matches = evaluate_signature_rules(active_rules, raw_bytes, report.image.get());
    }

    if (options.include_strings) {
        report.strings_included = true;
        report.strings = extract_headless_strings(
            *report.image, raw_bytes, options.min_string_length, options.max_strings);
    }

    if (options.compare_path.has_value()) {
        BinaryDiffOptions diff_opts;
        diff_opts.lhs_label = options.binary_path.filename().string();
        diff_opts.rhs_label = options.compare_path->filename().string();
        if (open_opts->selected_slice_index.has_value()) {
            diff_opts.lhs_slice_index = *open_opts->selected_slice_index;
        } else if (!open_opts->preferred_arch_name.empty()) {
            diff_opts.lhs_arch_name = open_opts->preferred_arch_name;
        }
        auto cmp = compare_binary_files(options.binary_path, *options.compare_path, diff_opts);
        if (!cmp.has_value()) {
            return std::unexpected(cmp.error());
        }
        report.comparison = std::move(*cmp);
    }

    return report;
}

std::string format_headless_report_json(const HeadlessAnalysisReport& report) {
    const IBinaryImage* img = report.image.get();
    ICrashDumpSession* dump = report.crash_dump.get();
    std::string out;
    out.reserve(16384u);

    auto key = [&](std::string_view k) {
        append_json_escaped(out, k);
        out += ": ";
    };

    out += "{\n";
    out += "  \"schema_version\": 1,\n";

    // Binary / dump identity
    out += "  \"binary\": {\n";
    out += "    "; key("path"); append_json_escaped(out, report.binary_path.generic_string()); out += ",\n";
    out += "    "; key("sha256"); append_json_escaped(out, report.sha256); out += ",\n";
    out += std::format("    \"size\": {},\n", report.file_size);
    if (dump != nullptr) {
        const CrashDumpSummary& cs = dump->crash_summary();
        const std::string_view fmt_str =
            cs.kind == CrashDumpKind::WindowsMinidump
                ? "Minidump"
                : (cs.kind == CrashDumpKind::MachOCore ? "Mach-O" : "ELF");
        out += "    "; key("format"); append_json_escaped(out, fmt_str); out += ",\n";
        out += "    "; key("kind"); append_json_escaped(out, "CrashDump"); out += ",\n";
        out += "    "; key("arch"); append_json_escaped(out, to_string(cs.layout.architecture)); out += ",\n";
        out += std::format("    \"bits\": {},\n", cs.layout.address_width == AddressWidth::Bits64 ? 64 : 32);
        out += "    "; key("endianness"); append_json_escaped(out, to_string(cs.layout.endianness)); out += ",\n";
        const std::uint64_t ep = img != nullptr
            ? img->entry_point()
            : (cs.exception.has_value() ? cs.exception->instruction_pointer.value_or(0u) : 0u);
        const std::uint64_t ib = img != nullptr ? img->image_base() : 0u;
        out += std::format("    \"entry_point\": {},\n", ep);
        out += std::format("    \"image_base\": {}\n", ib);
    } else {
        out += "    "; key("format"); append_json_escaped(out, to_string(img->format())); out += ",\n";
        out += "    "; key("kind"); append_json_escaped(out, to_string(img->kind())); out += ",\n";
        out += "    "; key("arch"); append_json_escaped(out, to_string(img->architecture())); out += ",\n";
        out += std::format("    \"bits\": {},\n", img->is_64bit() ? 64 : 32);
        out += "    "; key("endianness"); append_json_escaped(out, to_string(img->endianness())); out += ",\n";
        out += std::format("    \"entry_point\": {},\n", img->entry_point());
        out += std::format("    \"image_base\": {},\n", img->image_base());
        out += std::format("    \"universal_container\": {},\n",
                           report.container_info.is_universal_container ? "true" : "false");
        out += std::format("    \"slice_count\": {},\n",
                           std::max<std::size_t>(report.container_info.slices.size(), 1u));
        out += std::format("    \"selected_slice_index\": {},\n", report.selected_slice_index);
        out += "    "; key("selected_slice_arch"); append_json_escaped(out, report.selected_slice_arch); out += ",\n";
        out += std::format("    \"selected_slice_offset\": {},\n", img->container_slice_offset());
        out += std::format("    \"selected_slice_size\": {}\n",
                           img->container_slice_size() != 0u ? img->container_slice_size() : report.file_size);
    }
    out += "  },\n";

    // Target profile, capture provenance, and validated capability matrix (WU-21)
    out += "  \"target_profile\": {\n";
    out += "    "; key("format"); append_json_escaped(out, to_string(report.target_profile.format)); out += ",\n";
    out += "    "; key("architecture"); append_json_escaped(out, to_string(report.target_profile.architecture)); out += ",\n";
    out += "    "; key("endianness"); append_json_escaped(out, to_string(report.target_profile.endianness)); out += ",\n";
    out += std::format("    \"address_width_bits\": {},\n",
                       report.target_profile.address_width == AddressWidth::Bits64 ? 64 : 32);
    out += "    "; key("abi"); append_json_escaped(out, to_string(report.target_profile.abi)); out += ",\n";
    out += "    "; key("os"); append_json_escaped(out, to_string(report.target_profile.os)); out += ",\n";
    out += "    "; key("backend"); append_json_escaped(out, to_string(report.target_profile.backend)); out += ",\n";
    out += std::format("    \"completely_specified\": {}\n",
                       report.target_profile.is_completely_specified() ? "true" : "false");
    out += "  },\n";

    out += "  \"provenance\": {\n";
    out += "    "; key("primary_source"); append_json_escaped(out, to_string(report.primary_provenance)); out += ",\n";
    out += std::format("    \"snapshot_revision\": {},\n", report.analysis_stamp.snapshot_revision);
    out += "    "; key("captured_at_utc"); append_json_escaped(out, report.analysis_stamp.captured_at_utc); out += ",\n";
    out += std::format("    \"target_paused\": {},\n", report.analysis_stamp.target_paused ? "true" : "false");
    out += "    "; key("availability"); append_json_escaped(out, to_string(report.analysis_stamp.availability)); out += ",\n";
    out += "    \"target_instance\": {\n";
    out += "      "; key("backend"); append_json_escaped(out, to_string(report.analysis_stamp.target_id.backend)); out += ",\n";
    out += std::format("      \"pid\": {},\n",
                       report.analysis_stamp.target_id.pid != 0u
                           ? std::to_string(report.analysis_stamp.target_id.pid)
                           : "null");
    out += std::format("      \"creation_identity\": {},\n",
                       report.analysis_stamp.target_id.creation_identity.has_value()
                           ? std::to_string(*report.analysis_stamp.target_id.creation_identity)
                           : "null");
    out += "      "; key("image_sha256"); append_json_escaped(out, report.analysis_stamp.target_id.image_sha256); out += ",\n";
    out += "      "; key("build_id_or_pdb_guid"); append_json_escaped(out, report.analysis_stamp.target_id.build_id_or_pdb_guid); out += "\n";
    out += "    }\n";
    out += "  },\n";

    out += "  \"capabilities\": [\n";
    const auto cap_entries = report.capabilities.entries();
    for (std::size_t i = 0; i < cap_entries.size(); ++i) {
        const Capability& cap = cap_entries[i];
        out += "    { ";
        key("operation"); append_json_escaped(out, to_string(cap.operation)); out += ", ";
        key("state"); append_json_escaped(out, to_string(cap.state));
        out += std::format(", \"provider_available\": {}, \"usable_now\": {}, ",
                           cap.provider_available ? "true" : "false",
                           cap.is_usable_now() ? "true" : "false");
        key("reason"); append_json_escaped(out, cap.reason);
        out += (i + 1u < cap_entries.size()) ? " },\n" : " }\n";
    }
    out += "  ],\n";

    static const std::vector<Section> kEmptySecs{};
    static const std::vector<ImportEntry> kEmptyImps{};
    static const std::vector<ExportEntry> kEmptyExps{};
    static const std::vector<Symbol> kEmptySyms{};

    // Sections
    out += "  \"sections\": [";
    const auto& secs = img != nullptr ? img->sections() : kEmptySecs;
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
    const auto& imps = img != nullptr ? img->imports() : kEmptyImps;
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
    const auto& exps = img != nullptr ? img->exports() : kEmptyExps;
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
    out += std::format("    \"system_shared_cache\": {},\n", ds.system_shared_cache);
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
    const auto& syms = img != nullptr ? img->symbols() : kEmptySyms;
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

    // Offline Crash Dump Summary (`WU-14`)
    if (dump != nullptr) {
        const CrashDumpSummary& cs = dump->crash_summary();
        out += "  \"crash_dump\": {\n";
        out += "    "; key("kind"); append_json_escaped(out, to_string(cs.kind)); out += ",\n";
        out += "    "; key("os_summary"); append_json_escaped(out, cs.os_summary); out += ",\n";
        out += "    "; key("cpu_summary"); append_json_escaped(out, cs.cpu_summary); out += ",\n";
        out += std::format("    \"pid\": {},\n", cs.pid);
        out += std::format("    \"parent_pid\": {},\n", cs.parent_pid);
        out += "    "; key("process_name"); append_json_escaped(out, cs.process_name); out += ",\n";
        out += "    "; key("command_line"); append_json_escaped(out, cs.command_line); out += ",\n";

        out += "    \"exception\": ";
        if (cs.exception.has_value()) {
            const CrashExceptionInfo& ex = *cs.exception;
            out += "{\n";
            out += std::format("      \"thread_id\": {},\n",
                               ex.thread_id.has_value() ? std::to_string(*ex.thread_id) : "null");
            out += std::format("      \"code\": {},\n", ex.fault_code);
            out += "      "; key("name"); append_json_escaped(out, ex.fault_name); out += ",\n";
            out += std::format("      \"fault_address\": {},\n",
                               ex.fault_address.has_value() ? std::to_string(*ex.fault_address) : "null");
            out += std::format("      \"instruction_pointer\": {},\n",
                               ex.instruction_pointer.has_value() ? std::to_string(*ex.instruction_pointer) : "null");
            out += "      "; key("access_operation"); append_json_escaped(out, ex.access_operation); out += ",\n";
            out += "      "; key("description"); append_json_escaped(out, ex.description); out += "\n";
            out += "    },\n";
        } else {
            out += "null,\n";
        }

        const auto mods = dump->modules();
        out += "    \"modules\": [";
        if (mods.has_value()) {
            for (std::size_t i = 0; i < mods->size(); ++i) {
                const ModuleInfo& m = (*mods)[i];
                out += (i == 0u) ? "\n" : ",\n";
                out += "      { ";
                key("name"); append_json_escaped(out, m.name); out += ", ";
                key("path"); append_json_escaped(out, m.path.generic_string());
                out += std::format(", \"base_address\": {}, \"size\": {}, \"entry_point\": {}, \"is_main_module\": {} }}",
                                   m.base_address,
                                   m.size,
                                   m.entry_point,
                                   m.is_main_module ? "true" : "false");
            }
            if (!mods->empty()) out += "\n    ";
        }
        out += "],\n";

        const auto ths = dump->threads();
        out += "    \"threads\": [";
        if (ths.has_value()) {
            for (std::size_t i = 0; i < ths->size(); ++i) {
                const ThreadInfo& th = (*ths)[i];
                const ThreadContext ctx = dump->thread_context(th.tid);
                out += (i == 0u) ? "\n" : ",\n";
                out += "      { ";
                out += std::format("\"tid\": {}, ", th.tid);
                key("name"); append_json_escaped(out, th.name); out += ", ";
                key("state"); append_json_escaped(out, to_string(th.state));
                out += std::format(", \"instruction_pointer\": {}, \"stack_pointer\": {}, \"frame_pointer\": {}, \"tls_base\": {}, \"registers\": [",
                                   ctx.instruction_pointer,
                                   ctx.stack_pointer,
                                   ctx.frame_pointer,
                                   th.tls_base.value_or(0u));
                for (std::size_t r = 0; r < ctx.registers.size(); ++r) {
                    const RegisterValue& rv = ctx.registers[r];
                    if (r > 0u) out += ", ";
                    out += "{ ";
                    key("name"); append_json_escaped(out, rv.name);
                    out += std::format(", \"value\": {} }}", rv.value_u64);
                }
                out += "] }";
            }
            if (!ths->empty()) out += "\n    ";
        }
        out += "],\n";

        const auto regs = dump->memory_regions();
        out += "    \"memory_regions\": [";
        if (regs.has_value()) {
            for (std::size_t i = 0; i < regs->size(); ++i) {
                const MemoryRegion& reg = (*regs)[i];
                out += (i == 0u) ? "\n" : ",\n";
                out += std::format("      {{ \"start_address\": {}, \"end_address\": {}, \"size\": {}, ",
                                   reg.start_address,
                                   reg.end_address,
                                   reg.size());
                key("protection"); append_json_escaped(out, format_protection(reg.protection)); out += ", ";
                key("kind"); append_json_escaped(out, to_string(reg.kind)); out += ", ";
                key("pathname"); append_json_escaped(out, reg.pathname);
                out += std::format(", \"file_offset\": {} }}", reg.file_offset);
            }
            if (!regs->empty()) out += "\n    ";
        }
        out += "]\n  },\n";
    }

    // Unified Executable & Settings Overview (`WU-22` / `WU-23`)
    out += "  \"executable_settings\": ";
    out += format_executable_settings_json(report.executable_settings, 2u);
    out += ",\n";

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
    out += "]\n  },\n";

    // PE Rich Header (`WU-38`)
    out += "  \"pe_rich_header\": ";
    if (report.pe_rich_header.has_value()) {
        const PeRichHeader& rh = *report.pe_rich_header;
        out += "{\n";
        out += std::format("    \"dans_offset\": {},\n", rh.dans_offset);
        out += std::format("    \"rich_offset\": {},\n", rh.rich_offset);
        out += std::format("    \"byte_length\": {},\n", rh.byte_length);
        out += std::format("    \"xor_key\": {},\n", rh.xor_key);
        out += std::format("    \"computed_checksum\": {},\n", rh.computed_checksum);
        out += std::format("    \"checksum_valid\": {},\n", rh.checksum_valid ? "true" : "false");
        out += std::format("    \"padding_valid\": {},\n", rh.padding_valid ? "true" : "false");
        out += "    "; key("diagnostic"); append_json_escaped(out, rh.diagnostic); out += ",\n";
        out += "    \"entries\": [";
        for (std::size_t i = 0u; i < rh.entries.size(); ++i) {
            const PeRichCompIdEntry& e = rh.entries[i];
            out += (i == 0u) ? "\n" : ",\n";
            out += std::format("      {{ \"prod_id\": {}, \"build_number\": {}, \"use_count\": {}, ",
                               e.prod_id,
                               e.build_number,
                               e.use_count);
            key("tool_category"); append_json_escaped(out, e.tool_category);
            out += std::format(", \"file_offset\": {} }}", e.file_offset);
        }
        if (!rh.entries.empty()) out += "\n    ";
        out += "]\n  },\n";
    } else {
        out += "null,\n";
    }

    // Crypto, Hash, Compression & Packer Constant Hits (`WU-38`)
    out += "  \"crypto_signatures\": [";
    for (std::size_t i = 0u; i < report.crypto_hits.size(); ++i) {
        const CryptoSignatureHit& ch = report.crypto_hits[i];
        out += (i == 0u) ? "\n" : ",\n";
        out += "    { ";
        key("id"); append_json_escaped(out, ch.id); out += ", ";
        key("category"); append_json_escaped(out, ch.category); out += ", ";
        key("algorithm"); append_json_escaped(out, ch.algorithm); out += ", ";
        key("summary"); append_json_escaped(out, ch.summary); out += ", ";
        key("confidence"); append_json_escaped(out, ch.confidence);
        out += std::format(", \"file_offset\": {}, \"virtual_address\": {}, \"byte_length\": {}, ",
                           ch.file_offset.has_value() ? std::to_string(*ch.file_offset) : "null",
                           ch.virtual_address.has_value() ? std::to_string(*ch.virtual_address) : "null",
                           ch.byte_length);
        key("section_name"); append_json_escaped(out, ch.section_name);
        out += " }";
    }
    if (!report.crypto_hits.empty()) out += "\n  ";
    out += "],\n";

    // YARA-Lite Signature Rule Matches (`WU-38`)
    out += "  \"rule_matches\": [";
    for (std::size_t i = 0u; i < report.rule_matches.size(); ++i) {
        const SignatureRuleMatch& rm = report.rule_matches[i];
        out += (i == 0u) ? "\n" : ",\n";
        out += "    {\n";
        out += "      "; key("rule_name"); append_json_escaped(out, rm.rule_name); out += ",\n";
        out += "      \"tags\": [";
        for (std::size_t t = 0u; t < rm.tags.size(); ++t) {
            if (t > 0u) out += ", ";
            append_json_escaped(out, rm.tags[t]);
        }
        out += "],\n";
        out += "      "; key("description"); append_json_escaped(out, rm.description); out += ",\n";
        out += "      "; key("severity"); append_json_escaped(out, rm.severity); out += ",\n";
        out += "      "; key("author"); append_json_escaped(out, rm.author); out += ",\n";
        out += "      "; key("source_name"); append_json_escaped(out, rm.source_name); out += ",\n";
        out += std::format("      \"total_match_count\": {},\n", rm.total_match_count);
        out += "      \"string_matches\": [";
        for (std::size_t sm_i = 0u; sm_i < rm.string_matches.size(); ++sm_i) {
            const SignatureStringMatch& sm = rm.string_matches[sm_i];
            out += (sm_i == 0u) ? "\n" : ",\n";
            out += "        { ";
            key("identifier"); append_json_escaped(out, sm.identifier);
            out += std::format(", \"file_offset\": {}, \"virtual_address\": {}, \"byte_length\": {}, ",
                               sm.file_offset.has_value() ? std::to_string(*sm.file_offset) : "null",
                               sm.virtual_address.has_value() ? std::to_string(*sm.virtual_address) : "null",
                               sm.byte_length);
            key("section_name"); append_json_escaped(out, sm.section_name); out += ", ";
            key("matched_preview"); append_json_escaped(out, sm.matched_preview);
            out += " }";
        }
        if (!rm.string_matches.empty()) out += "\n      ";
        out += "]\n    }";
    }
    if (!report.rule_matches.empty()) out += "\n  ";
    out += "]";

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

    auto sarif_level = [](SecuritySeverity sev) noexcept -> std::string_view {
        switch (sev) {
            case SecuritySeverity::Pass:    return "none";
            case SecuritySeverity::Note:    return "note";
            case SecuritySeverity::Warning: return "warning";
            case SecuritySeverity::Error:   return "error";
        }
        return "note";
    };

    auto signature_sarif_level = [](std::string_view sev) -> std::string_view {
        const std::string low = lower_ascii(sev);
        if (low == "error" || low == "high" || low == "critical") {
            return "error";
        }
        if (low == "note" || low == "info" || low == "informational") {
            return "note";
        }
        return "warning";
    };

    struct SarifDriverRuleEntry {
        std::string id{};
        std::string name{};
        std::string short_description{};
        std::string help_text{};
        std::string default_level{};
    };

    const auto catalog = security_rule_catalog();
    std::unordered_map<std::string, std::size_t> rule_index_by_id;
    std::vector<SarifDriverRuleEntry> active_rules;
    for (const SecurityFinding& f : report.security.findings) {
        for (const SecurityRuleDescriptor& desc : catalog) {
            if (desc.id == f.rule_id && !rule_index_by_id.contains(std::string(desc.id))) {
                rule_index_by_id.emplace(std::string(desc.id), active_rules.size());
                active_rules.push_back(SarifDriverRuleEntry{
                    .id = std::string(desc.id),
                    .name = std::string(desc.name),
                    .short_description = std::string(desc.short_description),
                    .help_text = std::string(desc.help_text),
                    .default_level = std::string(sarif_level(desc.default_failure_severity)),
                });
                break;
            }
        }
    }
    for (const SignatureRuleMatch& rm : report.rule_matches) {
        if (!rule_index_by_id.contains(rm.rule_name)) {
            rule_index_by_id.emplace(rm.rule_name, active_rules.size());
            const std::string desc_text = rm.description.empty()
                                              ? std::format("YARA-lite signature rule {}", rm.rule_name)
                                              : rm.description;
            const std::string help_str = std::format(
                "YARA-lite signature rule '{}' (source: '{}') matched target binary.",
                rm.rule_name,
                rm.source_name.empty() ? "builtin" : rm.source_name);
            active_rules.push_back(SarifDriverRuleEntry{
                .id = rm.rule_name,
                .name = rm.rule_name,
                .short_description = desc_text,
                .help_text = help_str,
                .default_level = std::string(signature_sarif_level(rm.severity)),
            });
        }
    }

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
        const SarifDriverRuleEntry& r = active_rules[i];
        out += (i == 0u) ? "\n" : ",\n";
        out += "            {\n";
        out += "              "; key("id"); append_json_escaped(out, r.id); out += ",\n";
        out += "              "; key("name"); append_json_escaped(out, r.name); out += ",\n";
        out += "              \"shortDescription\": { "; key("text"); append_json_escaped(out, r.short_description); out += " },\n";
        out += "              \"help\": { "; key("text"); append_json_escaped(out, r.help_text); out += " },\n";
        out += "              \"defaultConfiguration\": { ";
        key("level"); append_json_escaped(out, r.default_level);
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
    bool emitted_any_result = !report.security.findings.empty();
    for (std::size_t i = 0u; i < report.rule_matches.size(); ++i) {
        const SignatureRuleMatch& rm = report.rule_matches[i];
        out += (!emitted_any_result && i == 0u) ? "\n" : ",\n";
        emitted_any_result = true;
        out += "        {\n";
        out += "          "; key("ruleId"); append_json_escaped(out, rm.rule_name); out += ",\n";
        if (auto it = rule_index_by_id.find(rm.rule_name); it != rule_index_by_id.end()) {
            out += std::format("          \"ruleIndex\": {},\n", it->second);
        }
        out += "          \"kind\": \"fail\",\n";
        out += "          "; key("level"); append_json_escaped(out, signature_sarif_level(rm.severity)); out += ",\n";
        std::string msg = rm.description.empty()
                              ? std::format("Signature rule '{}' matched.", rm.rule_name)
                              : rm.description;
        if (!rm.string_matches.empty()) {
            const SignatureStringMatch& sm = rm.string_matches.front();
            if (sm.file_offset.has_value()) {
                msg += std::format(" First match: {} @ offset 0x{:X} ({}).",
                                   sm.identifier,
                                   *sm.file_offset,
                                   sm.matched_preview);
            } else if (sm.virtual_address.has_value()) {
                msg += std::format(" First match: {} @ VA 0x{:X} ({}).",
                                   sm.identifier,
                                   *sm.virtual_address,
                                   sm.matched_preview);
            }
        }
        out += "          \"message\": { "; key("text"); append_json_escaped(out, msg); out += " },\n";
        out += "          \"locations\": [\n";
        out += "            {\n";
        out += "              \"physicalLocation\": {\n";
        out += "                \"artifactLocation\": { ";
        key("uri"); append_json_escaped(out, artifact_uri);
        out += ", \"index\": 0 }";
        if (!rm.string_matches.empty()) {
            const SignatureStringMatch& sm = rm.string_matches.front();
            if (sm.virtual_address.has_value() || sm.file_offset.has_value() || !sm.section_name.empty()) {
                out += ",\n                \"address\": { ";
                bool need_comma = false;
                if (sm.virtual_address.has_value()) {
                    out += std::format("\"absoluteAddress\": {}", *sm.virtual_address);
                    need_comma = true;
                }
                if (sm.file_offset.has_value()) {
                    if (need_comma) out += ", ";
                    out += std::format("\"offsetFromParent\": {}", *sm.file_offset);
                    need_comma = true;
                }
                if (!sm.section_name.empty()) {
                    if (need_comma) out += ", ";
                    key("name"); append_json_escaped(out, sm.section_name);
                }
                out += " }";
            }
        }
        out += "\n              }\n";
        out += "            }\n";
        out += "          ]\n";
        out += "        }";
    }
    if (emitted_any_result) out += "\n      ";
    out += "]";

    // Optional properties block carrying dependency & comparison summary for CI tooling
    out += ",\n      \"properties\": {\n";
    out += std::format("        \"universalContainer\": {},\n",
                       report.container_info.is_universal_container ? "true" : "false");
    out += std::format("        \"selectedSliceIndex\": {},\n", report.selected_slice_index);
    out += "        "; key("selectedSliceArch"); append_json_escaped(out, report.selected_slice_arch); out += ",\n";
    out += std::format("        \"cryptoSignatureCount\": {},\n", report.crypto_hits.size());
    out += std::format("        \"ruleMatchCount\": {},\n", report.rule_matches.size());
    out += std::format("        \"systemSharedCacheLibraries\": {},\n", report.dependencies.summary.system_shared_cache);
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

    std::size_t rule_error_count = 0u;
    std::size_t rule_warning_count = 0u;
    for (const SignatureRuleMatch& rm : report.rule_matches) {
        const std::string low = lower_ascii(rm.severity);
        if (low == "error" || low == "high" || low == "critical") {
            ++rule_error_count;
        } else if (low != "note" && low != "info" && low != "informational") {
            ++rule_warning_count;
        }
    }

    if (fail_on == HeadlessFailPolicy::Error) {
        if (report.security.error_count > 0u || rule_error_count > 0u || has_dep_errors) {
            return 2;
        }
        return 0;
    }

    if (fail_on == HeadlessFailPolicy::Warning) {
        if (report.security.error_count > 0u ||
            report.security.warning_count > 0u ||
            rule_error_count > 0u ||
            rule_warning_count > 0u ||
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
            << "  --slice <index|arch>         Select Universal Mach-O slice by 0-based index or arch name\n"
            << "  --compare <other_binary>     Include static binary & relocation-tolerant function diff\n"
            << "  --format <json|sarif>        Output format (default: json; sarif emits SARIF 2.1.0)\n"
            << "  --output <path>              Write report atomically to <path> (default: stdout)\n"
            << "  --search-root <dir>          Extra dependency search directory (repeatable)\n"
            << "  --rules <path>               Evaluate custom YARA-lite rule file (repeatable)\n"
            << "  --no-builtin-rules           Disable built-in YARA-lite starter rule pack\n"
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
        const std::string_view raw_arg = args[i];
        if (raw_arg == "--headless") {
            continue;
        }
        std::string_view a = raw_arg;
        std::optional<std::string_view> inline_val;
        if (raw_arg.starts_with("--")) {
            if (const std::size_t eq = raw_arg.find('='); eq != std::string_view::npos) {
                a = raw_arg.substr(0u, eq);
                inline_val = raw_arg.substr(eq + 1u);
            }
        }
        auto require_next = [&](std::string_view flag) -> std::optional<std::string_view> {
            if (inline_val.has_value()) {
                return *inline_val;
            }
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
        } else if (a == "--slice") {
            auto val = require_next(a);
            if (!val) return 1;
            if (val->empty()) {
                stderr_stream << "Error: --slice requires a slice index or architecture name\n";
                return 1;
            }
            opts.slice_selector = std::string(*val);
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
        } else if (a == "--rules") {
            auto val = require_next(a);
            if (!val) return 1;
            if (val->empty()) {
                stderr_stream << "Error: --rules requires a non-empty rule file path\n";
                return 1;
            }
            opts.rule_paths.emplace_back(*val);
        } else if (a == "--no-builtin-rules") {
            opts.include_builtin_rules = false;
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
