#pragma once

#include <peelf/binary_image.hpp>
#include <peelf/forgiving.hpp>
#include <peelf/process.hpp>

#include <algorithm>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace peelf {

/// Execution or inspection backend hosting the current target.
enum class BackendKind : std::uint8_t {
    StaticFile = 0,
    LiveNativeReadOnly,
    CrashDumpMinidump,
    CrashDumpElfCore,
    ActiveDebugger,
    RemoteGdbRsp,
    Unknown,
    GdbRemote = RemoteGdbRsp,
};

using TargetSessionKind = BackendKind;

[[nodiscard]] constexpr std::string_view to_string(BackendKind kind) noexcept {
    switch (kind) {
        case BackendKind::StaticFile:         return "StaticFile";
        case BackendKind::LiveNativeReadOnly: return "LiveNativeReadOnly";
        case BackendKind::CrashDumpMinidump:  return "CrashDumpMinidump";
        case BackendKind::CrashDumpElfCore:   return "CrashDumpElfCore";
        case BackendKind::ActiveDebugger:     return "ActiveDebugger";
        case BackendKind::RemoteGdbRsp:       return "RemoteGdbRsp";
        case BackendKind::Unknown:            return "Unknown";
    }
    return "Unknown";
}

/// First-class provenance tag recording where a displayed or serialized fact came from.
enum class ProvenanceTag : std::uint8_t {
    DiskFile = 0,
    DebugSymbols,
    LiveMemory,
    ProcOrOsApi,
    CrashDump,
    HeuristicInference,
    DebuggerShadowed,
    UserAnnotated,
    DecompilerSynthesized,
};

[[nodiscard]] constexpr std::string_view to_string(ProvenanceTag tag) noexcept {
    switch (tag) {
        case ProvenanceTag::DiskFile:              return "DiskFile";
        case ProvenanceTag::DebugSymbols:          return "DebugSymbols";
        case ProvenanceTag::LiveMemory:            return "LiveMemory";
        case ProvenanceTag::ProcOrOsApi:           return "ProcOrOsApi";
        case ProvenanceTag::CrashDump:             return "CrashDump";
        case ProvenanceTag::HeuristicInference:    return "HeuristicInference";
        case ProvenanceTag::DebuggerShadowed:      return "DebuggerShadowed";
        case ProvenanceTag::UserAnnotated:         return "UserAnnotated";
        case ProvenanceTag::DecompilerSynthesized: return "DecompilerSynthesized";
    }
    return "DiskFile";
}

/// Collection/value capture state. Named `CaptureAvailability` to coexist cleanly
/// with `peelf::Availability` in `<peelf/forgiving.hpp>`.
enum class CaptureAvailability : std::uint8_t {
    Complete = 0,
    Partial,
    Stale,
    Unavailable,
    Redacted,
};

[[nodiscard]] constexpr std::string_view to_string(CaptureAvailability avail) noexcept {
    switch (avail) {
        case CaptureAvailability::Complete:    return "Complete";
        case CaptureAvailability::Partial:     return "Partial";
        case CaptureAvailability::Stale:       return "Stale";
        case CaptureAvailability::Unavailable: return "Unavailable";
        case CaptureAvailability::Redacted:    return "Redacted";
    }
    return "Unavailable";
}

[[nodiscard]] constexpr CaptureAvailability to_capture_availability(
    Availability forgiving_avail) noexcept {
    switch (forgiving_avail) {
        case Availability::Available:   return CaptureAvailability::Complete;
        case Availability::Partial:     return CaptureAvailability::Partial;
        case Availability::Unavailable: return CaptureAvailability::Unavailable;
    }
    return CaptureAvailability::Unavailable;
}

[[nodiscard]] constexpr Availability to_forgiving_availability(
    CaptureAvailability capture_avail) noexcept {
    switch (capture_avail) {
        case CaptureAvailability::Complete:    return Availability::Available;
        case CaptureAvailability::Partial:     return Availability::Partial;
        case CaptureAvailability::Stale:       return Availability::Partial;
        case CaptureAvailability::Redacted:    return Availability::Partial;
        case CaptureAvailability::Unavailable: return Availability::Unavailable;
    }
    return Availability::Unavailable;
}

/// Stable identity of an inspected target instance. Incorporates OS process creation
/// identity (Linux `/proc/<pid>/stat` field 22 `starttime` ticks or Win32
/// `GetProcessTimes` `CreationTime`) so PID reuse never silently equates two targets.
struct TargetInstanceId {
    BackendKind backend{BackendKind::StaticFile};
    ProcessId pid{0};
    std::optional<std::uint64_t> creation_identity{};
    std::string image_sha256{};
    std::string build_id_or_pdb_guid{};
    std::uint64_t session_nonce{0};
    std::uint64_t dump_nonce{0};

    [[nodiscard]] bool same_instance(const TargetInstanceId& other) const noexcept {
        if (backend != other.backend) {
            return false;
        }
        const std::uint64_t lhs_nonce = dump_nonce != 0u ? dump_nonce : session_nonce;
        const std::uint64_t rhs_nonce =
            other.dump_nonce != 0u ? other.dump_nonce : other.session_nonce;

        if (backend == BackendKind::StaticFile ||
            backend == BackendKind::CrashDumpMinidump ||
            backend == BackendKind::CrashDumpElfCore) {
            if (!image_sha256.empty() || !other.image_sha256.empty()) {
                return !image_sha256.empty() && image_sha256 == other.image_sha256;
            }
            if (!build_id_or_pdb_guid.empty() || !other.build_id_or_pdb_guid.empty()) {
                if (build_id_or_pdb_guid.empty() ||
                    build_id_or_pdb_guid != other.build_id_or_pdb_guid) {
                    return false;
                }
                if (backend == BackendKind::StaticFile && lhs_nonce == 0u && rhs_nonce == 0u) {
                    return pid == other.pid;
                }
            }
            return (pid == other.pid) && (lhs_nonce != 0u) && (lhs_nonce == rhs_nonce);
        }

        // Live / debugger / remote process backends: PID must match and creation
        // identity must agree whenever either capture recorded one.
        if (pid == 0u || pid != other.pid) {
            return false;
        }
        if (creation_identity.has_value() || other.creation_identity.has_value()) {
            return creation_identity.has_value() &&
                   other.creation_identity.has_value() &&
                   *creation_identity == *other.creation_identity;
        }
        return lhs_nonce != 0u && lhs_nonce == rhs_nonce;
    }

    auto operator<=>(const TargetInstanceId&) const = default;
};

/// Per-collection capture metadata. Separate subsystems (`MemoryMap`, `Threads`,
/// `RuntimeStructures`, `ProcessInternals`) maintain independent `CaptureStamp`s
/// so UI and JSON consumers never conflate captures from different points in time.
struct CaptureStamp {
    TargetInstanceId target_id{};
    std::uint64_t snapshot_revision{0};
    std::string captured_at_utc{};
    std::uint64_t captured_unix_ms{0};
    std::uint64_t monotonic_ns{0};
    bool target_paused{false};
    CaptureAvailability availability{CaptureAvailability::Unavailable};

    [[nodiscard]] static CaptureStamp capture_now(
        const TargetInstanceId& target,
        std::uint64_t revision,
        bool paused,
        CaptureAvailability avail = CaptureAvailability::Complete);

    [[nodiscard]] static CaptureStamp unavailable_for(
        const TargetInstanceId& target = {}) {
        CaptureStamp st;
        st.target_id = target;
        st.availability = CaptureAvailability::Unavailable;
        return st;
    }

    [[nodiscard]] constexpr bool has_capture() const noexcept {
        return snapshot_revision != 0u && availability != CaptureAvailability::Unavailable;
    }

    [[nodiscard]] constexpr bool is_stale_relative_to(
        std::uint64_t latest_revision) const noexcept {
        if (availability == CaptureAvailability::Stale) {
            return true;
        }
        if (!has_capture()) {
            return false;
        }
        return !target_paused && snapshot_revision < latest_revision;
    }

    auto operator<=>(const CaptureStamp&) const = default;
};

/// Concrete provenance record explaining a single source contributing to an `Observed<T>`.
struct Evidence {
    ProvenanceTag tag{ProvenanceTag::DiskFile};
    std::string source{};
    std::string detail{};
    std::optional<std::uint64_t> virtual_address{};
    std::optional<std::uint64_t> file_offset{};

    auto operator<=>(const Evidence&) const = default;
};

/// Provenance-carrying envelope wrapping any extracted, live-sampled, or inferred value.
template <typename T>
struct Observed {
    std::optional<T> value{};
    ProvenanceTag provenance{ProvenanceTag::DiskFile};
    CaptureAvailability availability{CaptureAvailability::Unavailable};
    CaptureStamp stamp{};
    std::vector<Evidence> evidence{};
    std::string note{};

    [[nodiscard]] constexpr bool has_value() const noexcept { return value.has_value(); }
    [[nodiscard]] constexpr explicit operator bool() const noexcept { return value.has_value(); }

    [[nodiscard]] constexpr bool is_complete() const noexcept {
        return availability == CaptureAvailability::Complete && value.has_value();
    }
    [[nodiscard]] constexpr bool is_partial() const noexcept {
        return availability == CaptureAvailability::Partial;
    }
    [[nodiscard]] constexpr bool is_stale() const noexcept {
        return availability == CaptureAvailability::Stale || stamp.availability == CaptureAvailability::Stale;
    }
    [[nodiscard]] constexpr bool is_unavailable() const noexcept {
        return availability == CaptureAvailability::Unavailable;
    }
    [[nodiscard]] constexpr bool is_redacted() const noexcept {
        return availability == CaptureAvailability::Redacted;
    }

    [[nodiscard]] bool has_mixed_provenance() const noexcept {
        if (evidence.empty()) {
            return false;
        }
        const ProvenanceTag first = evidence.front().tag;
        return std::ranges::any_of(evidence, [first](const Evidence& ev) {
            return ev.tag != first;
        });
    }

    [[nodiscard]] bool is_mixed_source() const noexcept {
        return has_mixed_provenance();
    }

    [[nodiscard]] std::vector<ProvenanceTag> distinct_provenance_tags() const {
        std::vector<ProvenanceTag> out;
        auto add_unique = [&out](ProvenanceTag t) {
            if (std::ranges::find(out, t) == out.end()) {
                out.push_back(t);
            }
        };
        if (evidence.empty()) {
            add_unique(provenance);
            return out;
        }
        for (const Evidence& ev : evidence) {
            add_unique(ev.tag);
        }
        return out;
    }

    void add_evidence(Evidence ev) {
        evidence.push_back(std::move(ev));
    }

    void mark_stale(std::string_view note = {}) {
        if (availability == CaptureAvailability::Complete ||
            availability == CaptureAvailability::Partial) {
            availability = CaptureAvailability::Stale;
        }
        if (stamp.availability == CaptureAvailability::Complete ||
            stamp.availability == CaptureAvailability::Partial) {
            stamp.availability = CaptureAvailability::Stale;
        }
        if (!note.empty()) {
            evidence.push_back(Evidence{
                .tag = provenance,
                .source = "revision_tracker",
                .detail = std::string(note),
            });
        }
    }

    [[nodiscard]] static Observed<T> complete(
        T val,
        ProvenanceTag tag,
        CaptureStamp capture_stamp = {},
        std::vector<Evidence> ev = {}) {
        capture_stamp.availability = CaptureAvailability::Complete;
        if (ev.empty()) {
            ev.push_back(Evidence{.tag = tag, .source = std::string(to_string(tag))});
        }
        return Observed<T>{
            .value = std::move(val),
            .provenance = tag,
            .availability = CaptureAvailability::Complete,
            .stamp = std::move(capture_stamp),
            .evidence = std::move(ev),
        };
    }

    [[nodiscard]] static Observed<T> partial(
        std::optional<T> val,
        ProvenanceTag tag,
        std::string_view reason,
        CaptureStamp capture_stamp = {},
        std::vector<Evidence> ev = {}) {
        capture_stamp.availability = CaptureAvailability::Partial;
        ev.push_back(Evidence{
            .tag = tag,
            .source = std::string(to_string(tag)),
            .detail = std::string(reason),
        });
        return Observed<T>{
            .value = std::move(val),
            .provenance = tag,
            .availability = CaptureAvailability::Partial,
            .stamp = std::move(capture_stamp),
            .evidence = std::move(ev),
            .note = std::string(reason),
        };
    }

    [[nodiscard]] static Observed<T> unavailable(
        ProvenanceTag tag,
        std::string_view reason,
        CaptureStamp capture_stamp = {}) {
        capture_stamp.availability = CaptureAvailability::Unavailable;
        return Observed<T>{
            .value = std::nullopt,
            .provenance = tag,
            .availability = CaptureAvailability::Unavailable,
            .stamp = std::move(capture_stamp),
            .evidence = {Evidence{
                .tag = tag,
                .source = std::string(to_string(tag)),
                .detail = std::string(reason),
            }},
            .note = std::string(reason),
        };
    }

    [[nodiscard]] static Observed<T> redacted(
        std::optional<T> placeholder_val,
        ProvenanceTag tag,
        std::string_view reason,
        CaptureStamp capture_stamp = {}) {
        capture_stamp.availability = CaptureAvailability::Redacted;
        return Observed<T>{
            .value = std::move(placeholder_val),
            .provenance = tag,
            .availability = CaptureAvailability::Redacted,
            .stamp = std::move(capture_stamp),
            .evidence = {Evidence{
                .tag = tag,
                .source = std::string(to_string(tag)),
                .detail = std::string(reason),
            }},
            .note = std::string(reason),
        };
    }

    [[nodiscard]] static Observed<T> from_forgiving(
        ForgivingValue<T> fv,
        ProvenanceTag tag,
        CaptureStamp capture_stamp = {}) {
        const CaptureAvailability avail = to_capture_availability(fv.status.availability);
        capture_stamp.availability = avail;
        std::vector<Evidence> ev;
        ev.push_back(Evidence{
            .tag = tag,
            .source = fv.status.source.empty() ? std::string(to_string(tag)) : fv.status.source,
            .detail = fv.status.detail,
        });
        return Observed<T>{
            .value = std::move(fv.value),
            .provenance = tag,
            .availability = avail,
            .stamp = std::move(capture_stamp),
            .evidence = std::move(ev),
        };
    }
};

/// Build/link identity extracted from an on-disk or memory-mapped binary image.
struct BackingImageIdentity {
    Format format{Format::Unknown};
    Architecture architecture{Architecture::Unknown};
    AddressWidth address_width{AddressWidth::Bits64};
    Endianness endianness{Endianness::Little};

    // PE build identifiers
    std::optional<std::uint32_t> pe_time_date_stamp{};
    std::optional<std::uint32_t> pe_size_of_image{};
    std::optional<std::uint32_t> pe_checksum{};
    std::string codeview_guid_hex{};
    std::optional<std::uint32_t> codeview_age{};

    // ELF build identifiers
    std::string elf_build_id_hex{};
    std::optional<std::uint32_t> elf_gnu_debuglink_crc32{};

    // Mach-O build identifier (LC_UUID) & slice CPU metadata
    std::string macho_uuid_hex{};
    std::optional<std::uint32_t> macho_cpu_type{};
    std::optional<std::uint32_t> macho_cpu_subtype{};

    // Optional whole-file hash, backing path, or explicit dump nonce
    std::string file_sha256{};
    std::string backing_path{};
    std::uint64_t dump_nonce{0};

    [[nodiscard]] std::string primary_identifier() const;

    [[nodiscard]] bool same_identity(const BackingImageIdentity& other) const noexcept {
        if (format == Format::Unknown || other.format == Format::Unknown ||
            format != other.format || architecture != other.architecture ||
            address_width != other.address_width || endianness != other.endianness) {
            return false;
        }
        if (macho_cpu_type.has_value() && other.macho_cpu_type.has_value() &&
            *macho_cpu_type != *other.macho_cpu_type) {
            return false;
        }
        if (macho_cpu_subtype.has_value() && other.macho_cpu_subtype.has_value() &&
            *macho_cpu_subtype != *other.macho_cpu_subtype) {
            return false;
        }

        bool any_explicit_field = false;
        if (!elf_build_id_hex.empty() || !other.elf_build_id_hex.empty()) {
            if (elf_build_id_hex != other.elf_build_id_hex) {
                return false;
            }
            any_explicit_field = true;
        }
        if (!macho_uuid_hex.empty() || !other.macho_uuid_hex.empty()) {
            if (macho_uuid_hex != other.macho_uuid_hex) {
                return false;
            }
            any_explicit_field = true;
        }
        if (!codeview_guid_hex.empty() || !other.codeview_guid_hex.empty()) {
            if (codeview_guid_hex != other.codeview_guid_hex ||
                codeview_age != other.codeview_age) {
                return false;
            }
            any_explicit_field = true;
        }
        if (pe_time_date_stamp.has_value() || other.pe_time_date_stamp.has_value()) {
            if (pe_time_date_stamp != other.pe_time_date_stamp ||
                pe_size_of_image != other.pe_size_of_image) {
                return false;
            }
            any_explicit_field = true;
        }
        if (!file_sha256.empty() || !other.file_sha256.empty()) {
            if (file_sha256 != other.file_sha256) {
                return false;
            }
            any_explicit_field = true;
        }
        if (!backing_path.empty() || !other.backing_path.empty()) {
            if (backing_path != other.backing_path) {
                return false;
            }
            any_explicit_field = true;
        }

        if (any_explicit_field) {
            return dump_nonce == 0u || other.dump_nonce == 0u || dump_nonce == other.dump_nonce;
        }
        return dump_nonce != 0u && dump_nonce == other.dump_nonce;
    }
};

/// Result of comparing an on-disk backing file's build identity against a live or dump module.
struct BackingIdentityMatchResult {
    bool comparable{false};
    bool matches{true};
    std::string disk_identifier{};
    std::string live_identifier{};
    std::string summary{};
    std::vector<std::string> mismatches{};

    [[nodiscard]] constexpr bool has_mismatch() const noexcept {
        return comparable && !matches;
    }
};

/// Format a UTC timestamp (`YYYY-MM-DDTHH:MM:SS.mmmZ`) from Unix epoch milliseconds.
[[nodiscard]] std::string format_utc_iso8601_ms(std::uint64_t unix_epoch_ms);

/// Parse field 22 (`starttime` in clock ticks since boot) from a Linux `/proc/<pid>/stat` line,
/// safely handling executable `comm` names containing spaces or nested parentheses.
[[nodiscard]] std::optional<std::uint64_t> parse_linux_proc_stat_starttime(
    std::string_view proc_stat_line) noexcept;

/// Query the OS-specific process creation identity for `pid` when accessible
/// (Linux `/proc/<pid>/stat` `starttime`, Windows `GetProcessTimes` `CreationTime`).
[[nodiscard]] std::optional<std::uint64_t> query_process_creation_identity(ProcessId pid) noexcept;

/// Extract `BackingImageIdentity` from a parsed `IBinaryImage` and optional raw file bytes.
[[nodiscard]] BackingImageIdentity extract_backing_image_identity(
    const IBinaryImage& image,
    std::span<const std::uint8_t> raw_file_bytes = {});

/// Compare on-disk vs. live/mapped `BackingImageIdentity` records and flag build-ID,
/// RSDS GUID+Age, or PE header mismatches so stale/rebuilt disk binaries are never
/// silently conflated with live process memory.
[[nodiscard]] BackingIdentityMatchResult verify_backing_image_identity(
    const BackingImageIdentity& disk_identity,
    const BackingImageIdentity& live_identity);

/// Read a bounded header/note window from `live_module` in `session` and compare its
/// in-memory build identity against `disk_image`.
[[nodiscard]] BackingIdentityMatchResult verify_live_module_backing_identity(
    const IBinaryImage& disk_image,
    std::span<const std::uint8_t> disk_file_bytes,
    IProcessSession& session,
    const ModuleInfo& live_module,
    std::span<const MemoryRegion> regions = {});

} // namespace peelf
