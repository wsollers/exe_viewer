#include <peelf/process_snapshot.hpp>

#include <peelf/capability_matrix.hpp>
#include <peelf/gdb_remote.hpp>

#include <algorithm>
#include <atomic>
#include <cctype>
#include <cstdint>
#include <filesystem>
#include <format>
#include <fstream>
#include <limits>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#endif

namespace peelf {

namespace {

std::atomic<std::uint64_t> g_next_snapshot_revision{1u};

[[nodiscard]] std::uint64_t next_snapshot_revision() noexcept {
    return g_next_snapshot_revision.fetch_add(1u, std::memory_order_relaxed);
}

[[nodiscard]] constexpr std::int64_t signed_delta_clamped(
    std::uint64_t before_val,
    std::uint64_t after_val) noexcept {
    constexpr auto kMaxI64 = static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::max());
    if (after_val >= before_val) {
        const std::uint64_t diff = after_val - before_val;
        if (diff > kMaxI64) {
            return std::numeric_limits<std::int64_t>::max();
        }
        return static_cast<std::int64_t>(diff);
    }
    const std::uint64_t diff = before_val - after_val;
    if (diff > kMaxI64) {
        return std::numeric_limits<std::int64_t>::min();
    }
    return -static_cast<std::int64_t>(diff);
}

[[nodiscard]] std::string ascii_lower_copy(std::string_view sv) {
    std::string out;
    out.reserve(sv.size());
    for (const char ch : sv) {
        out.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(ch))));
    }
    return out;
}

[[nodiscard]] bool looks_like_pe_module_path(std::string_view path_or_name) noexcept {
    const auto ends_icase = [](std::string_view s, std::string_view sfx) noexcept -> bool {
        if (s.size() < sfx.size()) {
            return false;
        }
        const std::size_t start = s.size() - sfx.size();
        for (std::size_t i = 0u; i < sfx.size(); ++i) {
            const auto ca = static_cast<char>(std::tolower(static_cast<unsigned char>(s[start + i])));
            const auto cb = static_cast<char>(std::tolower(static_cast<unsigned char>(sfx[i])));
            if (ca != cb) {
                return false;
            }
        }
        return true;
    };
    return ends_icase(path_or_name, ".dll") || ends_icase(path_or_name, ".exe") ||
           ends_icase(path_or_name, ".sys") || ends_icase(path_or_name, ".ocx") ||
           path_or_name.find('\\') != std::string_view::npos;
}

[[nodiscard]] constexpr std::string_view strip_deleted_view(std::string_view sv) noexcept {
    constexpr std::string_view kDeletedSuffix = " (deleted)";
    if (sv.ends_with(kDeletedSuffix)) {
        sv.remove_suffix(kDeletedSuffix.size());
    }
    return sv;
}

[[nodiscard]] std::string normalize_module_identity_key(const ModuleInfo& mod) {
    const std::string raw_path = mod.path.generic_string();
    const std::string_view cleaned_path = strip_deleted_view(raw_path);
    if (!cleaned_path.empty()) {
        if (looks_like_pe_module_path(cleaned_path)) {
            return ascii_lower_copy(cleaned_path);
        }
        return std::string(cleaned_path);
    }
    const std::string_view cleaned_name = strip_deleted_view(mod.name);
    if (looks_like_pe_module_path(cleaned_name)) {
        return ascii_lower_copy(cleaned_name);
    }
    return std::string(cleaned_name);
}

[[nodiscard]] std::string module_display_label(const ModuleInfo& mod) {
    if (!mod.name.empty()) {
        return mod.name;
    }
    if (!mod.path.empty()) {
        return mod.path.filename().string();
    }
    return std::format("module@0x{:X}", mod.base_address);
}

[[nodiscard]] const BackingImageIdentity* find_module_backing_identity(
    std::span<const std::pair<std::uint64_t, BackingImageIdentity>> identities,
    std::uint64_t base_address) noexcept {
    for (const auto& entry : identities) {
        if (entry.first == base_address) {
            return &entry.second;
        }
    }
    return nullptr;
}

[[nodiscard]] bool module_backing_identities_conflict(
    const BackingImageIdentity* before_id,
    const BackingImageIdentity* after_id) {
    if (before_id == nullptr || after_id == nullptr) {
        return false;
    }
    return verify_backing_image_identity(*before_id, *after_id).has_mismatch();
}

[[nodiscard]] TargetInstanceId derive_session_target_id(const IProcessSession& session) {
    TargetInstanceId tid{};
    const bool is_gdb_remote = (dynamic_cast<const IGdbRemoteSession*>(&session) != nullptr);
    if (session.is_crash_dump()) {
        const std::string lower_exe = ascii_lower_copy(session.info().executable_path.generic_string());
        tid.backend = lower_exe.ends_with(".dmp") || lower_exe.ends_with(".mdmp")
                          ? BackendKind::CrashDumpMinidump
                          : BackendKind::CrashDumpElfCore;
    } else if (is_gdb_remote) {
        tid.backend = BackendKind::GdbRemote;
    } else if (!session.is_read_only()) {
        tid.backend = BackendKind::ActiveDebugger;
    } else {
        tid.backend = BackendKind::LiveNativeReadOnly;
    }

    tid.pid = session.pid();
    if (!session.is_crash_dump() && !is_gdb_remote && tid.pid != 0u) {
        tid.creation_identity = query_process_creation_identity(tid.pid);
    }
    if (!tid.creation_identity.has_value()) {
        const auto raw_ptr = reinterpret_cast<std::uintptr_t>(&session);
        tid.session_nonce = raw_ptr != 0u ? static_cast<std::uint64_t>(raw_ptr) : 1u;
    }
    return tid;
}

[[nodiscard]] CaptureAvailability map_subsystem_availability(Availability avail) noexcept {
    switch (avail) {
        case Availability::Available:   return CaptureAvailability::Complete;
        case Availability::Partial:     return CaptureAvailability::Partial;
        case Availability::Unavailable: return CaptureAvailability::Unavailable;
    }
    return CaptureAvailability::Unavailable;
}

[[nodiscard]] std::string format_protection_short(const MemoryProtection& prot) {
    std::string out = "---";
    if (prot.readable) {
        out[0] = 'R';
    }
    if (prot.writable) {
        out[1] = 'W';
    }
    if (prot.executable) {
        out[2] = 'X';
    }
    return out;
}

[[nodiscard]] const MemoryRegion* find_covering_region(
    std::span<const MemoryRegion> regions,
    std::uint64_t seg_start,
    std::uint64_t seg_end) noexcept {
    const MemoryRegion* best = nullptr;
    std::uint64_t best_span = std::numeric_limits<std::uint64_t>::max();
    for (const MemoryRegion& reg : regions) {
        if (reg.end_address <= reg.start_address) {
            continue;
        }
        if (reg.start_address <= seg_start && reg.end_address >= seg_end) {
            const std::uint64_t span = reg.end_address - reg.start_address;
            if (best == nullptr || span < best_span) {
                best = &reg;
                best_span = span;
            }
        }
    }
    return best;
}

[[nodiscard]] bool region_backing_conflicts(
    const MemoryRegion& before_reg,
    const MemoryRegion& after_reg) noexcept {
    const std::string_view b_path = strip_deleted_view(before_reg.pathname);
    const std::string_view a_path = strip_deleted_view(after_reg.pathname);
    if (b_path != a_path) {
        return true;
    }
    if (!b_path.empty() && before_reg.kind != after_reg.kind) {
        return true;
    }
    if (b_path.empty() && before_reg.kind != after_reg.kind &&
        (before_reg.kind == MemoryRegionKind::Image ||
         after_reg.kind == MemoryRegionKind::Image ||
         before_reg.kind == MemoryRegionKind::MappedFile ||
         after_reg.kind == MemoryRegionKind::MappedFile)) {
        return true;
    }
    return false;
}

[[nodiscard]] DiffUncertaintyKind classify_partial_pair(
    CaptureAvailability before_avail,
    CaptureAvailability after_avail) noexcept {
    const bool b_incomplete = (before_avail != CaptureAvailability::Complete);
    const bool a_incomplete = (after_avail != CaptureAvailability::Complete);
    if (b_incomplete && a_incomplete) {
        return DiffUncertaintyKind::PartialBothCaptures;
    }
    if (b_incomplete) {
        return DiffUncertaintyKind::PartialBeforeCapture;
    }
    return DiffUncertaintyKind::PartialAfterCapture;
}

void append_partial_uncertainty(
    std::vector<SnapshotUncertainty>& out,
    DiffDomain domain,
    CaptureAvailability before_avail,
    CaptureAvailability after_avail,
    std::size_t suppressed_removals,
    std::size_t suppressed_additions) {
    SnapshotUncertainty unc{};
    unc.domain = domain;
    unc.kind = classify_partial_pair(before_avail, after_avail);
    unc.before_availability = before_avail;
    unc.after_availability = after_avail;
    unc.suppressed_removal_count = suppressed_removals;
    unc.suppressed_addition_count = suppressed_additions;
    unc.message = std::format(
        "{} diff has non-complete capture (before={}, after={}); suppressed {} unverified removal(s) and {} unverified addition(s).",
        to_string(domain),
        to_string(before_avail),
        to_string(after_avail),
        suppressed_removals,
        suppressed_additions);
    out.push_back(std::move(unc));
}

void append_unavailable_uncertainty(
    std::vector<SnapshotUncertainty>& out,
    DiffDomain domain,
    CaptureAvailability before_avail,
    CaptureAvailability after_avail,
    std::string_view before_note,
    std::string_view after_note) {
    SnapshotUncertainty unc{};
    unc.domain = domain;
    unc.kind = DiffUncertaintyKind::CollectionUnavailable;
    unc.before_availability = before_avail;
    unc.after_availability = after_avail;
    unc.message = std::format(
        "{} diff unavailable (before={}{}, after={}{}); no removals or additions inferred.",
        to_string(domain),
        to_string(before_avail),
        before_note.empty() ? "" : std::format(" [{}]", before_note),
        to_string(after_avail),
        after_note.empty() ? "" : std::format(" [{}]", after_note));
    out.push_back(std::move(unc));
}

[[nodiscard]] bool same_thread_instance(
    const ThreadSnapshot& before_t,
    const ThreadSnapshot& after_t) noexcept {
    if (before_t.info.tid != after_t.info.tid) {
        return false;
    }
    if (before_t.creation_identity.has_value() && after_t.creation_identity.has_value()) {
        return *before_t.creation_identity == *after_t.creation_identity;
    }
    if (before_t.info.start_address.has_value() && after_t.info.start_address.has_value() &&
        *before_t.info.start_address != 0u && *after_t.info.start_address != 0u) {
        return *before_t.info.start_address == *after_t.info.start_address;
    }
    return true;
}

[[nodiscard]] std::optional<std::uint64_t> effective_thread_ip(
    const ThreadSnapshot& snap) noexcept {
    if (snap.context.has_value() && !snap.context.is_unavailable() &&
        snap.context.value->instruction_pointer != 0u) {
        return snap.context.value->instruction_pointer;
    }
    return snap.info.instruction_pointer;
}

[[nodiscard]] std::optional<std::uint64_t> effective_thread_sp(
    const ThreadSnapshot& snap) noexcept {
    if (snap.context.has_value() && !snap.context.is_unavailable() &&
        snap.context.value->stack_pointer != 0u) {
        return snap.context.value->stack_pointer;
    }
    return snap.info.stack_pointer;
}

[[nodiscard]] bool same_handle_backing(
    const ProcessHandleEntry& before_h,
    const ProcessHandleEntry& after_h) noexcept {
    if (before_h.handle_or_fd != after_h.handle_or_fd) {
        return false;
    }
    if (before_h.kind != after_h.kind) {
        return false;
    }
    if (!before_h.type_name.empty() && !after_h.type_name.empty() &&
        before_h.type_name != after_h.type_name) {
        return false;
    }
    if (before_h.inode.has_value() && after_h.inode.has_value() &&
        *before_h.inode != *after_h.inode) {
        return false;
    }
    if (before_h.mount_id.has_value() && after_h.mount_id.has_value() &&
        *before_h.mount_id != *after_h.mount_id) {
        return false;
    }
    const std::string_view b_target = strip_deleted_view(before_h.target);
    const std::string_view a_target = strip_deleted_view(after_h.target);
    if (b_target != a_target) {
        const bool same_inode_and_mount =
            before_h.inode.has_value() && after_h.inode.has_value() &&
            *before_h.inode != 0u && *before_h.inode == *after_h.inode &&
            before_h.mount_id.has_value() && after_h.mount_id.has_value() &&
            *before_h.mount_id == *after_h.mount_id;
        if (!same_inode_and_mount) {
            return false;
        }
    }
    return true;
}

[[nodiscard]] bool same_socket_identity(
    const ProcessSocketEntry& before_s,
    const ProcessSocketEntry& after_s) noexcept {
    if (before_s.protocol != after_s.protocol) {
        return false;
    }
    if (before_s.inode != 0u && after_s.inode != 0u) {
        if (before_s.inode != after_s.inode) {
            return false;
        }
        if (before_s.fd.has_value() && after_s.fd.has_value()) {
            return *before_s.fd == *after_s.fd;
        }
        return true;
    }
    if (before_s.inode != after_s.inode) {
        return false;
    }
    if (before_s.fd != after_s.fd) {
        return false;
    }
    return before_s.local_endpoint == after_s.local_endpoint &&
           before_s.remote_endpoint == after_s.remote_endpoint;
}

void diff_modules(
    const ProcessStateSnapshot& before,
    const ProcessStateSnapshot& after,
    SnapshotDiff& diff) {
    const CaptureAvailability b_avail = before.modules.availability;
    const CaptureAvailability a_avail = after.modules.availability;
    if (!before.modules.has_value() || !after.modules.has_value() ||
        b_avail == CaptureAvailability::Unavailable ||
        a_avail == CaptureAvailability::Unavailable) {
        append_unavailable_uncertainty(
            diff.uncertainties,
            DiffDomain::Modules,
            b_avail,
            a_avail,
            before.modules.note,
            after.modules.note);
        return;
    }

    const auto& b_mods = *before.modules.value;
    const auto& a_mods = *after.modules.value;
    const bool b_complete = (b_avail == CaptureAvailability::Complete);
    const bool a_complete = (a_avail == CaptureAvailability::Complete);

    std::vector<std::string> b_keys;
    b_keys.reserve(b_mods.size());
    for (const ModuleInfo& m : b_mods) {
        b_keys.push_back(normalize_module_identity_key(m));
    }

    std::vector<std::string> a_keys;
    a_keys.reserve(a_mods.size());
    for (const ModuleInfo& m : a_mods) {
        a_keys.push_back(normalize_module_identity_key(m));
    }

    std::vector<std::uint8_t> b_matched(b_mods.size(), 0u);
    std::vector<std::uint8_t> a_matched(a_mods.size(), 0u);

    // Pass 1: exact (base_address, normalized_backing_key) match without strong identity conflict.
    for (std::size_t bi = 0u; bi < b_mods.size(); ++bi) {
        const ModuleInfo& bm = b_mods[bi];
        const BackingImageIdentity* b_id =
            find_module_backing_identity(before.module_identities, bm.base_address);
        for (std::size_t ai = 0u; ai < a_mods.size(); ++ai) {
            if (a_matched[ai] != 0u) {
                continue;
            }
            const ModuleInfo& am = a_mods[ai];
            if (bm.base_address != am.base_address || b_keys[bi] != a_keys[ai]) {
                continue;
            }
            const BackingImageIdentity* a_id =
                find_module_backing_identity(after.module_identities, am.base_address);
            if (module_backing_identities_conflict(b_id, a_id)) {
                continue;
            }
            b_matched[bi] = 1u;
            a_matched[ai] = 1u;
            if (bm.size != am.size || bm.entry_point != am.entry_point) {
                ModuleDelta delta{};
                delta.kind = ModuleDeltaKind::Modified;
                delta.before = bm;
                delta.after = am;
                delta.detail = std::format(
                    "{} modified in place at 0x{:X} (size 0x{:X} -> 0x{:X}).",
                    module_display_label(am),
                    am.base_address,
                    bm.size,
                    am.size);
                diff.modules.push_back(std::move(delta));
            }
            break;
        }
    }

    // Pass 2: unique relocation match when both captures are Complete.
    if (b_complete && a_complete) {
        for (std::size_t bi = 0u; bi < b_mods.size(); ++bi) {
            if (b_matched[bi] != 0u || b_keys[bi].empty()) {
                continue;
            }
            std::size_t b_same_key_count = 0u;
            for (std::size_t bj = 0u; bj < b_mods.size(); ++bj) {
                if (b_matched[bj] == 0u && b_keys[bj] == b_keys[bi]) {
                    ++b_same_key_count;
                }
            }
            if (b_same_key_count != 1u) {
                continue;
            }

            std::size_t candidate_ai = a_mods.size();
            std::size_t a_same_key_count = 0u;
            for (std::size_t ai = 0u; ai < a_mods.size(); ++ai) {
                if (a_matched[ai] == 0u && a_keys[ai] == b_keys[bi]) {
                    candidate_ai = ai;
                    ++a_same_key_count;
                }
            }
            if (a_same_key_count != 1u || candidate_ai >= a_mods.size()) {
                continue;
            }

            const ModuleInfo& bm = b_mods[bi];
            const ModuleInfo& am = a_mods[candidate_ai];
            const BackingImageIdentity* b_id =
                find_module_backing_identity(before.module_identities, bm.base_address);
            const BackingImageIdentity* a_id =
                find_module_backing_identity(after.module_identities, am.base_address);
            if (module_backing_identities_conflict(b_id, a_id)) {
                continue;
            }

            b_matched[bi] = 1u;
            a_matched[candidate_ai] = 1u;
            ModuleDelta delta{};
            delta.kind = ModuleDeltaKind::Relocated;
            delta.before = bm;
            delta.after = am;
            delta.detail = std::format(
                "{} relocated from 0x{:X} to 0x{:X}.",
                module_display_label(am),
                bm.base_address,
                am.base_address);
            diff.modules.push_back(std::move(delta));
        }
    }

    // Pass 3: classify remaining unmatched before/after modules and flag VA reuse.
    std::size_t suppressed_removals = 0u;
    std::size_t suppressed_additions = 0u;

    for (std::size_t bi = 0u; bi < b_mods.size(); ++bi) {
        if (b_matched[bi] != 0u) {
            continue;
        }
        const ModuleInfo& bm = b_mods[bi];
        bool va_reused = false;
        bool id_changed = false;
        const BackingImageIdentity* b_id =
            find_module_backing_identity(before.module_identities, bm.base_address);
        for (std::size_t ai = 0u; ai < a_mods.size(); ++ai) {
            if (a_matched[ai] == 0u && a_mods[ai].base_address == bm.base_address) {
                va_reused = true;
                const BackingImageIdentity* a_id =
                    find_module_backing_identity(after.module_identities, a_mods[ai].base_address);
                if (module_backing_identities_conflict(b_id, a_id)) {
                    id_changed = true;
                }
                break;
            }
        }

        if (b_complete && a_complete) {
            ModuleDelta delta{};
            delta.kind = ModuleDeltaKind::Unloaded;
            delta.before = bm;
            delta.base_address_reused = va_reused;
            delta.backing_identity_changed = id_changed;
            delta.detail = va_reused
                               ? std::format(
                                     "{} unloaded from 0x{:X} (base address reused by another module).",
                                     module_display_label(bm),
                                     bm.base_address)
                               : std::format(
                                     "{} unloaded from 0x{:X}.",
                                     module_display_label(bm),
                                     bm.base_address);
            diff.modules.push_back(std::move(delta));
        } else {
            ++suppressed_removals;
        }
    }

    for (std::size_t ai = 0u; ai < a_mods.size(); ++ai) {
        if (a_matched[ai] != 0u) {
            continue;
        }
        const ModuleInfo& am = a_mods[ai];
        bool va_reused = false;
        bool id_changed = false;
        const BackingImageIdentity* a_id =
            find_module_backing_identity(after.module_identities, am.base_address);
        for (std::size_t bi = 0u; bi < b_mods.size(); ++bi) {
            if (b_matched[bi] == 0u && b_mods[bi].base_address == am.base_address) {
                va_reused = true;
                const BackingImageIdentity* b_id =
                    find_module_backing_identity(before.module_identities, b_mods[bi].base_address);
                if (module_backing_identities_conflict(b_id, a_id)) {
                    id_changed = true;
                }
                break;
            }
        }

        if (b_complete) {
            ModuleDelta delta{};
            delta.kind = ModuleDeltaKind::Loaded;
            delta.after = am;
            delta.base_address_reused = va_reused;
            delta.backing_identity_changed = id_changed;
            delta.detail = va_reused
                               ? std::format(
                                     "{} loaded at reused base address 0x{:X}.",
                                     module_display_label(am),
                                     am.base_address)
                               : std::format(
                                     "{} loaded at 0x{:X}.",
                                     module_display_label(am),
                                     am.base_address);
            diff.modules.push_back(std::move(delta));
        } else {
            ++suppressed_additions;
        }
    }

    if (!b_complete || !a_complete) {
        append_partial_uncertainty(
            diff.uncertainties,
            DiffDomain::Modules,
            b_avail,
            a_avail,
            suppressed_removals,
            suppressed_additions);
    }
}

void diff_regions(
    const ProcessStateSnapshot& before,
    const ProcessStateSnapshot& after,
    const SnapshotDiffOptions& options,
    SnapshotDiff& diff) {
    const CaptureAvailability b_avail = before.regions.availability;
    const CaptureAvailability a_avail = after.regions.availability;
    if (!before.regions.has_value() || !after.regions.has_value() ||
        b_avail == CaptureAvailability::Unavailable ||
        a_avail == CaptureAvailability::Unavailable) {
        append_unavailable_uncertainty(
            diff.uncertainties,
            DiffDomain::Regions,
            b_avail,
            a_avail,
            before.regions.note,
            after.regions.note);
        return;
    }

    const auto& b_regs = *before.regions.value;
    const auto& a_regs = *after.regions.value;
    const bool b_complete = (b_avail == CaptureAvailability::Complete);
    const bool a_complete = (a_avail == CaptureAvailability::Complete);

    std::vector<std::uint64_t> endpoints;
    endpoints.reserve((b_regs.size() + a_regs.size()) * 2u);
    for (const MemoryRegion& r : b_regs) {
        if (r.end_address > r.start_address) {
            endpoints.push_back(r.start_address);
            endpoints.push_back(r.end_address);
        }
    }
    for (const MemoryRegion& r : a_regs) {
        if (r.end_address > r.start_address) {
            endpoints.push_back(r.start_address);
            endpoints.push_back(r.end_address);
        }
    }
    std::ranges::sort(endpoints);
    const auto unique_tail = std::ranges::unique(endpoints);
    endpoints.erase(unique_tail.begin(), unique_tail.end());

    std::size_t suppressed_removals = 0u;
    std::size_t suppressed_additions = 0u;

    if (endpoints.size() >= 2u) {
        for (std::size_t i = 0u; i + 1u < endpoints.size(); ++i) {
            const std::uint64_t seg_start = endpoints[i];
            const std::uint64_t seg_end = endpoints[i + 1u];
            if (seg_end <= seg_start) {
                continue;
            }

            const MemoryRegion* b_cov = find_covering_region(b_regs, seg_start, seg_end);
            const MemoryRegion* a_cov = find_covering_region(a_regs, seg_start, seg_end);
            if (b_cov == nullptr && a_cov == nullptr) {
                continue;
            }

            if (b_cov == nullptr && a_cov != nullptr) {
                if (b_complete) {
                    RegionDelta delta{};
                    delta.kind = RegionDeltaKind::Mapped;
                    delta.start_address = seg_start;
                    delta.end_address = seg_end;
                    delta.after_protection = a_cov->protection;
                    delta.after_region = *a_cov;
                    delta.was_merged = (a_cov->start_address < seg_start ||
                                        a_cov->end_address > seg_end);
                    delta.became_rwx = a_cov->protection.writable && a_cov->protection.executable;
                    delta.became_executable = a_cov->protection.executable;
                    delta.detail = std::format(
                        "[0x{:X}, 0x{:X}) mapped {} ({}).",
                        seg_start,
                        seg_end,
                        format_protection_short(a_cov->protection),
                        a_cov->pathname.empty() ? std::string(to_string(a_cov->kind)) : a_cov->pathname);
                    diff.regions.push_back(std::move(delta));
                } else {
                    ++suppressed_additions;
                }
                continue;
            }

            if (b_cov != nullptr && a_cov == nullptr) {
                if (b_complete && a_complete) {
                    RegionDelta delta{};
                    delta.kind = RegionDeltaKind::Unmapped;
                    delta.start_address = seg_start;
                    delta.end_address = seg_end;
                    delta.before_protection = b_cov->protection;
                    delta.before_region = *b_cov;
                    delta.was_split = (b_cov->start_address < seg_start ||
                                       b_cov->end_address > seg_end);
                    delta.detail = std::format(
                        "[0x{:X}, 0x{:X}) unmapped (was {}).",
                        seg_start,
                        seg_end,
                        format_protection_short(b_cov->protection));
                    diff.regions.push_back(std::move(delta));
                } else {
                    ++suppressed_removals;
                }
                continue;
            }

            // Both b_cov and a_cov cover [seg_start, seg_end).
            const bool b_wider = (b_cov->start_address < seg_start || b_cov->end_address > seg_end);
            const bool a_wider = (a_cov->start_address < seg_start || a_cov->end_address > seg_end);
            const bool prot_changed = (b_cov->protection != a_cov->protection);
            const bool backing_changed = region_backing_conflicts(*b_cov, *a_cov);

            const bool before_wx = b_cov->protection.writable && b_cov->protection.executable;
            const bool after_wx = a_cov->protection.writable && a_cov->protection.executable;
            const bool became_rwx = !before_wx && after_wx;
            const bool became_exec = !b_cov->protection.executable && a_cov->protection.executable;
            const bool jit_transition =
                b_cov->protection.writable && !b_cov->protection.executable &&
                !a_cov->protection.writable && a_cov->protection.executable;

            std::optional<std::int64_t> d_rss{};
            std::optional<std::int64_t> d_pss{};
            std::optional<std::int64_t> d_swap{};
            bool resident_changed = false;
            if (!b_wider && !a_wider) {
                if (b_cov->usage.rss_bytes.has_value() && a_cov->usage.rss_bytes.has_value()) {
                    d_rss = signed_delta_clamped(*b_cov->usage.rss_bytes, *a_cov->usage.rss_bytes);
                    resident_changed = resident_changed || (*d_rss != 0);
                }
                if (b_cov->usage.pss_bytes.has_value() && a_cov->usage.pss_bytes.has_value()) {
                    d_pss = signed_delta_clamped(*b_cov->usage.pss_bytes, *a_cov->usage.pss_bytes);
                    resident_changed = resident_changed || (*d_pss != 0);
                }
                if (b_cov->usage.swap_bytes.has_value() && a_cov->usage.swap_bytes.has_value()) {
                    d_swap = signed_delta_clamped(*b_cov->usage.swap_bytes, *a_cov->usage.swap_bytes);
                    resident_changed = resident_changed || (*d_swap != 0);
                }
            }

            if (!prot_changed && !backing_changed && !b_wider && !a_wider &&
                (!options.include_resident_only_region_deltas || !resident_changed)) {
                continue;
            }

            RegionDelta delta{};
            delta.start_address = seg_start;
            delta.end_address = seg_end;
            delta.before_protection = b_cov->protection;
            delta.after_protection = a_cov->protection;
            delta.before_region = *b_cov;
            delta.after_region = *a_cov;
            delta.was_split = b_wider;
            delta.was_merged = a_wider;
            delta.va_reused = backing_changed;
            delta.became_rwx = became_rwx;
            delta.became_executable = became_exec;
            delta.jit_rw_to_rx = jit_transition;
            delta.delta_rss_bytes = d_rss;
            delta.delta_pss_bytes = d_pss;
            delta.delta_swap_bytes = d_swap;

            if (prot_changed) {
                delta.kind = RegionDeltaKind::ProtectionChanged;
                delta.detail = std::format(
                    "[0x{:X}, 0x{:X}) protection {} -> {}{}{}.",
                    seg_start,
                    seg_end,
                    format_protection_short(b_cov->protection),
                    format_protection_short(a_cov->protection),
                    became_rwx ? " (became RWX)" : (jit_transition ? " (RW->RX JIT transition)" : ""),
                    b_wider ? " [split]" : (a_wider ? " [merged]" : ""));
            } else if (backing_changed) {
                delta.kind = RegionDeltaKind::BackingChanged;
                delta.detail = std::format(
                    "[0x{:X}, 0x{:X}) backing changed ('{}' -> '{}').",
                    seg_start,
                    seg_end,
                    b_cov->pathname,
                    a_cov->pathname);
            } else if (b_wider) {
                delta.kind = RegionDeltaKind::Split;
                delta.detail = std::format(
                    "[0x{:X}, 0x{:X}) split from [0x{:X}, 0x{:X}) ({}).",
                    seg_start,
                    seg_end,
                    b_cov->start_address,
                    b_cov->end_address,
                    format_protection_short(a_cov->protection));
            } else if (a_wider) {
                delta.kind = RegionDeltaKind::Merged;
                delta.detail = std::format(
                    "[0x{:X}, 0x{:X}) merged into [0x{:X}, 0x{:X}) ({}).",
                    seg_start,
                    seg_end,
                    a_cov->start_address,
                    a_cov->end_address,
                    format_protection_short(a_cov->protection));
            } else {
                delta.kind = RegionDeltaKind::ResidentChanged;
                delta.detail = std::format(
                    "[0x{:X}, 0x{:X}) residency changed (dRSS={}).",
                    seg_start,
                    seg_end,
                    d_rss.value_or(0));
            }
            diff.regions.push_back(std::move(delta));
        }
    }

    if (!b_complete || !a_complete) {
        append_partial_uncertainty(
            diff.uncertainties,
            DiffDomain::Regions,
            b_avail,
            a_avail,
            suppressed_removals,
            suppressed_additions);
    }
}

void diff_threads(
    const ProcessStateSnapshot& before,
    const ProcessStateSnapshot& after,
    SnapshotDiff& diff) {
    const CaptureAvailability b_avail = before.threads.availability;
    const CaptureAvailability a_avail = after.threads.availability;
    if (!before.threads.has_value() || !after.threads.has_value() ||
        b_avail == CaptureAvailability::Unavailable ||
        a_avail == CaptureAvailability::Unavailable) {
        append_unavailable_uncertainty(
            diff.uncertainties,
            DiffDomain::Threads,
            b_avail,
            a_avail,
            before.threads.note,
            after.threads.note);
        return;
    }

    const auto& b_threads = *before.threads.value;
    const auto& a_threads = *after.threads.value;
    const bool b_complete = (b_avail == CaptureAvailability::Complete);
    const bool a_complete = (a_avail == CaptureAvailability::Complete);

    std::vector<std::uint8_t> b_matched(b_threads.size(), 0u);
    std::vector<std::uint8_t> a_matched(a_threads.size(), 0u);

    for (std::size_t bi = 0u; bi < b_threads.size(); ++bi) {
        const ThreadSnapshot& bt = b_threads[bi];
        for (std::size_t ai = 0u; ai < a_threads.size(); ++ai) {
            if (a_matched[ai] != 0u) {
                continue;
            }
            const ThreadSnapshot& at = a_threads[ai];
            if (!same_thread_instance(bt, at)) {
                continue;
            }
            b_matched[bi] = 1u;
            a_matched[ai] = 1u;

            const bool state_changed = (bt.info.state != at.info.state);
            const auto b_ip = effective_thread_ip(bt);
            const auto a_ip = effective_thread_ip(at);
            const bool ip_changed = b_ip.has_value() && a_ip.has_value() && (*b_ip != *a_ip);
            const auto b_sp = effective_thread_sp(bt);
            const auto a_sp = effective_thread_sp(at);
            const bool sp_changed = b_sp.has_value() && a_sp.has_value() && (*b_sp != *a_sp);
            const bool stack_changed =
                !bt.stack_bytes.valid.empty() && !at.stack_bytes.valid.empty() &&
                (bt.stack_capture_address != at.stack_capture_address ||
                 bt.stack_bytes.bytes != at.stack_bytes.bytes ||
                 bt.stack_bytes.valid != at.stack_bytes.valid);

            if (state_changed || ip_changed || sp_changed || stack_changed) {
                ThreadDelta delta{};
                delta.kind = ThreadDeltaKind::StateOrContextChanged;
                delta.tid = at.info.tid;
                delta.before = bt;
                delta.after = at;
                delta.state_changed = state_changed;
                delta.instruction_pointer_changed = ip_changed;
                delta.stack_pointer_changed = sp_changed;
                delta.stack_sample_changed = stack_changed;
                delta.detail = std::format(
                    "TID {} changed (state {} -> {}, IP {} -> {}).",
                    at.info.tid,
                    to_string(bt.info.state),
                    to_string(at.info.state),
                    b_ip.has_value() ? std::format("0x{:X}", *b_ip) : "n/a",
                    a_ip.has_value() ? std::format("0x{:X}", *a_ip) : "n/a");
                diff.threads.push_back(std::move(delta));
            }
            break;
        }
    }

    std::size_t suppressed_removals = 0u;
    std::size_t suppressed_additions = 0u;

    for (std::size_t bi = 0u; bi < b_threads.size(); ++bi) {
        if (b_matched[bi] != 0u) {
            continue;
        }
        const ThreadSnapshot& bt = b_threads[bi];
        bool tid_reused = false;
        for (std::size_t ai = 0u; ai < a_threads.size(); ++ai) {
            if (a_matched[ai] == 0u && a_threads[ai].info.tid == bt.info.tid) {
                tid_reused = true;
                break;
            }
        }

        if (b_complete && a_complete) {
            ThreadDelta delta{};
            delta.kind = ThreadDeltaKind::Exited;
            delta.tid = bt.info.tid;
            delta.before = bt;
            delta.tid_reused = tid_reused;
            delta.detail = tid_reused
                               ? std::format("TID {} exited and TID was reused by a new thread.", bt.info.tid)
                               : std::format("TID {} exited.", bt.info.tid);
            diff.threads.push_back(std::move(delta));
        } else {
            ++suppressed_removals;
        }
    }

    for (std::size_t ai = 0u; ai < a_threads.size(); ++ai) {
        if (a_matched[ai] != 0u) {
            continue;
        }
        const ThreadSnapshot& at = a_threads[ai];
        bool tid_reused = false;
        for (std::size_t bi = 0u; bi < b_threads.size(); ++bi) {
            if (b_matched[bi] == 0u && b_threads[bi].info.tid == at.info.tid) {
                tid_reused = true;
                break;
            }
        }

        if (b_complete || tid_reused) {
            ThreadDelta delta{};
            delta.kind = ThreadDeltaKind::Created;
            delta.tid = at.info.tid;
            delta.after = at;
            delta.tid_reused = tid_reused;
            delta.detail = tid_reused
                               ? std::format("TID {} created (reusing previous TID).", at.info.tid)
                               : std::format("TID {} created.", at.info.tid);
            diff.threads.push_back(std::move(delta));
        } else {
            ++suppressed_additions;
        }
    }

    if (!b_complete || !a_complete) {
        append_partial_uncertainty(
            diff.uncertainties,
            DiffDomain::Threads,
            b_avail,
            a_avail,
            suppressed_removals,
            suppressed_additions);
    }
}

void diff_handles(
    const ProcessStateSnapshot& before,
    const ProcessStateSnapshot& after,
    SnapshotDiff& diff) {
    const CaptureAvailability b_avail = before.handles.availability;
    const CaptureAvailability a_avail = after.handles.availability;
    if (!before.handles.has_value() || !after.handles.has_value() ||
        b_avail == CaptureAvailability::Unavailable ||
        a_avail == CaptureAvailability::Unavailable) {
        append_unavailable_uncertainty(
            diff.uncertainties,
            DiffDomain::Handles,
            b_avail,
            a_avail,
            before.handles.note,
            after.handles.note);
        return;
    }

    const auto& b_handles = *before.handles.value;
    const auto& a_handles = *after.handles.value;
    const bool b_complete = (b_avail == CaptureAvailability::Complete);
    const bool a_complete = (a_avail == CaptureAvailability::Complete);

    std::vector<std::uint8_t> b_matched(b_handles.size(), 0u);
    std::vector<std::uint8_t> a_matched(a_handles.size(), 0u);

    for (std::size_t bi = 0u; bi < b_handles.size(); ++bi) {
        const ProcessHandleEntry& bh = b_handles[bi];
        for (std::size_t ai = 0u; ai < a_handles.size(); ++ai) {
            if (a_matched[ai] != 0u) {
                continue;
            }
            const ProcessHandleEntry& ah = a_handles[ai];
            if (!same_handle_backing(bh, ah)) {
                continue;
            }
            b_matched[bi] = 1u;
            a_matched[ai] = 1u;
            if (bh.offset != ah.offset || bh.access_or_flags != ah.access_or_flags ||
                bh.target != ah.target) {
                HandleDelta delta{};
                delta.kind = HandleDeltaKind::Modified;
                delta.handle_or_fd = ah.handle_or_fd;
                delta.before = bh;
                delta.after = ah;
                delta.detail = std::format(
                    "Handle/FD {} ('{}') state modified.",
                    ah.handle_or_fd,
                    ah.target);
                diff.handles.push_back(std::move(delta));
            }
            break;
        }
    }

    std::size_t suppressed_removals = 0u;
    std::size_t suppressed_additions = 0u;

    for (std::size_t bi = 0u; bi < b_handles.size(); ++bi) {
        if (b_matched[bi] != 0u) {
            continue;
        }
        const ProcessHandleEntry& bh = b_handles[bi];
        bool fd_reused = false;
        for (std::size_t ai = 0u; ai < a_handles.size(); ++ai) {
            if (a_matched[ai] == 0u && a_handles[ai].handle_or_fd == bh.handle_or_fd) {
                fd_reused = true;
                break;
            }
        }

        if ((b_complete && a_complete) || fd_reused) {
            HandleDelta delta{};
            delta.kind = HandleDeltaKind::Closed;
            delta.handle_or_fd = bh.handle_or_fd;
            delta.before = bh;
            delta.fd_reused = fd_reused;
            delta.detail = fd_reused
                               ? std::format(
                                     "Handle/FD {} ('{}') closed and reused by another object.",
                                     bh.handle_or_fd,
                                     bh.target)
                               : std::format("Handle/FD {} ('{}') closed.", bh.handle_or_fd, bh.target);
            diff.handles.push_back(std::move(delta));
        } else {
            ++suppressed_removals;
        }
    }

    for (std::size_t ai = 0u; ai < a_handles.size(); ++ai) {
        if (a_matched[ai] != 0u) {
            continue;
        }
        const ProcessHandleEntry& ah = a_handles[ai];
        bool fd_reused = false;
        for (std::size_t bi = 0u; bi < b_handles.size(); ++bi) {
            if (b_matched[bi] == 0u && b_handles[bi].handle_or_fd == ah.handle_or_fd) {
                fd_reused = true;
                break;
            }
        }

        if (b_complete || fd_reused) {
            HandleDelta delta{};
            delta.kind = HandleDeltaKind::Opened;
            delta.handle_or_fd = ah.handle_or_fd;
            delta.after = ah;
            delta.fd_reused = fd_reused;
            delta.detail = fd_reused
                               ? std::format(
                                     "Handle/FD {} ('{}') opened (reusing previous descriptor).",
                                     ah.handle_or_fd,
                                     ah.target)
                               : std::format("Handle/FD {} ('{}') opened.", ah.handle_or_fd, ah.target);
            diff.handles.push_back(std::move(delta));
        } else {
            ++suppressed_additions;
        }
    }

    if (!b_complete || !a_complete) {
        append_partial_uncertainty(
            diff.uncertainties,
            DiffDomain::Handles,
            b_avail,
            a_avail,
            suppressed_removals,
            suppressed_additions);
    }
}

void diff_sockets(
    const ProcessStateSnapshot& before,
    const ProcessStateSnapshot& after,
    SnapshotDiff& diff) {
    const CaptureAvailability b_avail = before.sockets.availability;
    const CaptureAvailability a_avail = after.sockets.availability;
    if (!before.sockets.has_value() || !after.sockets.has_value() ||
        b_avail == CaptureAvailability::Unavailable ||
        a_avail == CaptureAvailability::Unavailable) {
        append_unavailable_uncertainty(
            diff.uncertainties,
            DiffDomain::Sockets,
            b_avail,
            a_avail,
            before.sockets.note,
            after.sockets.note);
        return;
    }

    const auto& b_socks = *before.sockets.value;
    const auto& a_socks = *after.sockets.value;
    const bool b_complete = (b_avail == CaptureAvailability::Complete);
    const bool a_complete = (a_avail == CaptureAvailability::Complete);

    std::vector<std::uint8_t> b_matched(b_socks.size(), 0u);
    std::vector<std::uint8_t> a_matched(a_socks.size(), 0u);

    for (std::size_t bi = 0u; bi < b_socks.size(); ++bi) {
        const ProcessSocketEntry& bs = b_socks[bi];
        for (std::size_t ai = 0u; ai < a_socks.size(); ++ai) {
            if (a_matched[ai] != 0u) {
                continue;
            }
            const ProcessSocketEntry& as = a_socks[ai];
            if (!same_socket_identity(bs, as)) {
                continue;
            }
            b_matched[bi] = 1u;
            a_matched[ai] = 1u;
            if (bs.state != as.state || bs.local_endpoint != as.local_endpoint ||
                bs.remote_endpoint != as.remote_endpoint) {
                SocketDelta delta{};
                delta.kind = SocketDeltaKind::StateChanged;
                delta.before = bs;
                delta.after = as;
                delta.detail = std::format(
                    "{} socket {} -> {} state '{}' -> '{}'.",
                    to_string(as.protocol),
                    as.local_endpoint,
                    as.remote_endpoint,
                    bs.state,
                    as.state);
                diff.sockets.push_back(std::move(delta));
            }
            break;
        }
    }

    std::size_t suppressed_removals = 0u;
    std::size_t suppressed_additions = 0u;

    for (std::size_t bi = 0u; bi < b_socks.size(); ++bi) {
        if (b_matched[bi] != 0u) {
            continue;
        }
        const ProcessSocketEntry& bs = b_socks[bi];
        bool reused = false;
        for (std::size_t ai = 0u; ai < a_socks.size(); ++ai) {
            if (a_matched[ai] != 0u) {
                continue;
            }
            const ProcessSocketEntry& as = a_socks[ai];
            const bool same_fd = bs.fd.has_value() && as.fd.has_value() && (*bs.fd == *as.fd);
            const bool same_tuple =
                bs.protocol == as.protocol && !bs.local_endpoint.empty() &&
                bs.local_endpoint == as.local_endpoint &&
                bs.remote_endpoint == as.remote_endpoint;
            if (same_fd || same_tuple) {
                reused = true;
                break;
            }
        }

        if ((b_complete && a_complete) || reused) {
            SocketDelta delta{};
            delta.kind = SocketDeltaKind::Closed;
            delta.before = bs;
            delta.fd_or_endpoint_reused = reused;
            delta.detail = reused
                               ? std::format(
                                     "{} socket {} -> {} closed (FD/endpoint reused).",
                                     to_string(bs.protocol),
                                     bs.local_endpoint,
                                     bs.remote_endpoint)
                               : std::format(
                                     "{} socket {} -> {} closed.",
                                     to_string(bs.protocol),
                                     bs.local_endpoint,
                                     bs.remote_endpoint);
            diff.sockets.push_back(std::move(delta));
        } else {
            ++suppressed_removals;
        }
    }

    for (std::size_t ai = 0u; ai < a_socks.size(); ++ai) {
        if (a_matched[ai] != 0u) {
            continue;
        }
        const ProcessSocketEntry& as = a_socks[ai];
        bool reused = false;
        for (std::size_t bi = 0u; bi < b_socks.size(); ++bi) {
            if (b_matched[bi] != 0u) {
                continue;
            }
            const ProcessSocketEntry& bs = b_socks[bi];
            const bool same_fd = bs.fd.has_value() && as.fd.has_value() && (*bs.fd == *as.fd);
            const bool same_tuple =
                bs.protocol == as.protocol && !bs.local_endpoint.empty() &&
                bs.local_endpoint == as.local_endpoint &&
                bs.remote_endpoint == as.remote_endpoint;
            if (same_fd || same_tuple) {
                reused = true;
                break;
            }
        }

        if (b_complete || reused) {
            SocketDelta delta{};
            delta.kind = SocketDeltaKind::Opened;
            delta.after = as;
            delta.fd_or_endpoint_reused = reused;
            delta.detail = reused
                               ? std::format(
                                     "{} socket {} -> {} opened (reusing previous FD/endpoint).",
                                     to_string(as.protocol),
                                     as.local_endpoint,
                                     as.remote_endpoint)
                               : std::format(
                                     "{} socket {} -> {} opened.",
                                     to_string(as.protocol),
                                     as.local_endpoint,
                                     as.remote_endpoint);
            diff.sockets.push_back(std::move(delta));
        } else {
            ++suppressed_additions;
        }
    }

    if (!b_complete || !a_complete) {
        append_partial_uncertainty(
            diff.uncertainties,
            DiffDomain::Sockets,
            b_avail,
            a_avail,
            suppressed_removals,
            suppressed_additions);
    }
}

}  // namespace

std::optional<std::uint64_t> query_thread_creation_identity(
    [[maybe_unused]] ProcessId pid,
    [[maybe_unused]] ThreadId tid) noexcept {
    if (pid == 0u || tid == 0u) {
        return std::nullopt;
    }
#ifdef __linux__
    try {
        const std::string stat_path =
            "/proc/" + std::to_string(pid) + "/task/" + std::to_string(tid) + "/stat";
        std::ifstream ifs(stat_path, std::ios::in | std::ios::binary);
        if (!ifs) {
            return std::nullopt;
        }
        std::string contents;
        std::getline(ifs, contents, '\0');
        return parse_linux_proc_stat_starttime(contents);
    } catch (...) {
        return std::nullopt;
    }
#elif defined(_WIN32)
    HANDLE th = ::OpenThread(THREAD_QUERY_LIMITED_INFORMATION, FALSE, static_cast<DWORD>(tid));
    if (th == nullptr) {
        return std::nullopt;
    }
    FILETIME creation{};
    FILETIME exit_t{};
    FILETIME kernel_t{};
    FILETIME user_t{};
    const BOOL ok = ::GetThreadTimes(th, &creation, &exit_t, &kernel_t, &user_t);
    ::CloseHandle(th);
    if (ok == FALSE) {
        return std::nullopt;
    }
    ULARGE_INTEGER uli{};
    uli.LowPart = creation.dwLowDateTime;
    uli.HighPart = creation.dwHighDateTime;
    return static_cast<std::uint64_t>(uli.QuadPart);
#else
    return std::nullopt;
#endif
}

ProcessStateSnapshot capture_process_snapshot(
    IProcessSession& session,
    const CaptureOptions& options) {
    ProcessStateSnapshot snapshot{};
    snapshot.target_id = options.target_id.has_value()
                             ? *options.target_id
                             : derive_session_target_id(session);
    snapshot.snapshot_revision = options.snapshot_revision != 0u
                                     ? options.snapshot_revision
                                     : next_snapshot_revision();
    snapshot.process_info = session.info();

    std::optional<ScopedProcessPause> pause_guard{};
    if (options.pause_target_during_capture && !session.is_suspended() &&
        !session.is_crash_dump() && session.is_alive()) {
        pause_guard.emplace(session);
    }
    const bool paused = session.is_suspended() || session.is_crash_dump();
    snapshot.paused_during_capture = paused;
    snapshot.snapshot_stamp = CaptureStamp::capture_now(
        snapshot.target_id, snapshot.snapshot_revision, paused, CaptureAvailability::Complete);

    const ProvenanceTag os_prov =
        session.is_crash_dump() ? ProvenanceTag::CrashDump : ProvenanceTag::ProcOrOsApi;
    const ProvenanceTag mem_prov =
        session.is_crash_dump() ? ProvenanceTag::CrashDump : ProvenanceTag::LiveMemory;

    if (!session.is_alive()) {
        const auto unavail_stamp = [&]() {
            return CaptureStamp::capture_now(
                snapshot.target_id, snapshot.snapshot_revision, paused, CaptureAvailability::Unavailable);
        };
        snapshot.snapshot_stamp = unavail_stamp();
        snapshot.regions = Observed<std::vector<MemoryRegion>>::unavailable(
            os_prov, "Target process is no longer alive.", unavail_stamp());
        snapshot.modules = Observed<std::vector<ModuleInfo>>::unavailable(
            os_prov, "Target process is no longer alive.", unavail_stamp());
        snapshot.threads = Observed<std::vector<ThreadSnapshot>>::unavailable(
            os_prov, "Target process is no longer alive.", unavail_stamp());
        snapshot.handles = Observed<std::vector<ProcessHandleEntry>>::unavailable(
            os_prov, "Target process is no longer alive.", unavail_stamp());
        snapshot.sockets = Observed<std::vector<ProcessSocketEntry>>::unavailable(
            os_prov, "Target process is no longer alive.", unavail_stamp());
        snapshot.security = Observed<ProcessSecurityProfile>::unavailable(
            os_prov, "Target process is no longer alive.", unavail_stamp());
        snapshot.launch_environment = Observed<LaunchEnvironmentSettings>::unavailable(
            os_prov, "Target process is no longer alive.", unavail_stamp());
        return snapshot;
    }

    // 1. Regions
    if (auto regs_res = session.memory_regions(); regs_res.has_value()) {
        const CaptureAvailability reg_avail =
            regs_res->empty() ? CaptureAvailability::Partial : CaptureAvailability::Complete;
        const CaptureStamp reg_stamp = CaptureStamp::capture_now(
            snapshot.target_id, snapshot.snapshot_revision, paused, reg_avail);
        if (reg_avail == CaptureAvailability::Complete) {
            snapshot.regions = Observed<std::vector<MemoryRegion>>::complete(
                std::move(*regs_res), os_prov, reg_stamp);
        } else {
            snapshot.regions = Observed<std::vector<MemoryRegion>>::partial(
                std::move(*regs_res),
                os_prov,
                "Memory region query succeeded but returned zero regions.",
                reg_stamp);
        }
    } else {
        const CaptureStamp reg_stamp = CaptureStamp::capture_now(
            snapshot.target_id, snapshot.snapshot_revision, paused, CaptureAvailability::Unavailable);
        snapshot.regions = Observed<std::vector<MemoryRegion>>::unavailable(
            os_prov, regs_res.error().message, reg_stamp);
    }

    const std::span<const MemoryRegion> regions_span =
        snapshot.regions.has_value()
            ? std::span<const MemoryRegion>(*snapshot.regions.value)
            : std::span<const MemoryRegion>{};

    // 2. Modules (+ optional bounded header identity probe)
    if (auto mods_res = session.modules(); mods_res.has_value()) {
        bool has_image_regions = false;
        for (const MemoryRegion& reg : regions_span) {
            if (reg.kind == MemoryRegionKind::Image) {
                has_image_regions = true;
                break;
            }
        }
        const CaptureAvailability mod_avail =
            (mods_res->empty() && has_image_regions)
                ? CaptureAvailability::Partial
                : CaptureAvailability::Complete;
        const CaptureStamp mod_stamp = CaptureStamp::capture_now(
            snapshot.target_id, snapshot.snapshot_revision, paused, mod_avail);
        if (mod_avail == CaptureAvailability::Complete) {
            snapshot.modules = Observed<std::vector<ModuleInfo>>::complete(
                std::move(*mods_res), os_prov, mod_stamp);
        } else {
            snapshot.modules = Observed<std::vector<ModuleInfo>>::partial(
                std::move(*mods_res),
                os_prov,
                "Module query returned empty despite mapped image regions.",
                mod_stamp);
        }

        if (options.probe_module_identities && snapshot.modules.has_value()) {
            constexpr std::uint64_t kMaxHeaderProbeBytes = 64ull * 1024ull;
            for (const ModuleInfo& mod : *snapshot.modules.value) {
                if (mod.base_address == 0u) {
                    continue;
                }
                const auto probe_len = static_cast<std::size_t>(std::min<std::uint64_t>(
                    mod.size > 0u ? mod.size : kMaxHeaderProbeBytes,
                    kMaxHeaderProbeBytes));
                const MemorySample hdr_sample =
                    read_memory_tolerant(session, regions_span, mod.base_address, probe_len);
                if (hdr_sample.readable_count < 64u) {
                    continue;
                }
                if (auto live_parsed = parse_mapped_image(hdr_sample.bytes, mod.base_address);
                    live_parsed.has_value() && *live_parsed != nullptr) {
                    BackingImageIdentity id = extract_backing_image_identity(**live_parsed);
                    if (id.format != Format::Unknown) {
                        snapshot.module_identities.emplace_back(mod.base_address, std::move(id));
                    }
                }
            }
        }
    } else {
        const CaptureStamp mod_stamp = CaptureStamp::capture_now(
            snapshot.target_id, snapshot.snapshot_revision, paused, CaptureAvailability::Unavailable);
        snapshot.modules = Observed<std::vector<ModuleInfo>>::unavailable(
            os_prov, mods_res.error().message, mod_stamp);
    }

    const std::span<const ModuleInfo> modules_span =
        snapshot.modules.has_value()
            ? std::span<const ModuleInfo>(*snapshot.modules.value)
            : std::span<const ModuleInfo>{};

    // 3. Threads (with per-thread creation identity, context, bounded stack bytes & top frames)
    if (auto threads_res = session.threads(); threads_res.has_value()) {
        std::vector<ThreadSnapshot> thread_snaps;
        thread_snaps.reserve(threads_res->size());
        bool any_partial_thread_entry = false;

        for (const ThreadInfo& th : *threads_res) {
            if (th.status.availability == Availability::Partial ||
                th.status.availability == Availability::Unavailable) {
                any_partial_thread_entry = true;
            }
            ThreadSnapshot ts{};
            ts.info = th;
            if (!session.is_crash_dump() &&
                dynamic_cast<const IGdbRemoteSession*>(&session) == nullptr) {
                ts.creation_identity = query_thread_creation_identity(session.pid(), th.tid);
            }

            if (options.capture_thread_contexts) {
                ThreadContext ctx = session.thread_context(th.tid);
                const CaptureAvailability ctx_avail =
                    map_subsystem_availability(ctx.status.availability);
                const CaptureStamp ctx_stamp = CaptureStamp::capture_now(
                    snapshot.target_id, snapshot.snapshot_revision, paused, ctx_avail);
                if (ctx_avail == CaptureAvailability::Unavailable) {
                    ts.context = Observed<ThreadContext>::unavailable(
                        os_prov, ctx.status.detail, ctx_stamp);
                } else {
                    if (!ts.info.instruction_pointer.has_value() && ctx.instruction_pointer != 0u) {
                        ts.info.instruction_pointer = ctx.instruction_pointer;
                    }
                    if (!ts.info.stack_pointer.has_value() && ctx.stack_pointer != 0u) {
                        ts.info.stack_pointer = ctx.stack_pointer;
                    }
                    if (ctx_avail == CaptureAvailability::Complete) {
                        ts.context = Observed<ThreadContext>::complete(
                            std::move(ctx), os_prov, ctx_stamp);
                    } else {
                        const std::string detail = ctx.status.detail;
                        ts.context = Observed<ThreadContext>::partial(
                            std::move(ctx), os_prov, detail, ctx_stamp);
                    }
                }
            } else {
                const CaptureStamp ctx_stamp = CaptureStamp::capture_now(
                    snapshot.target_id,
                    snapshot.snapshot_revision,
                    paused,
                    CaptureAvailability::Unavailable);
                ts.context = Observed<ThreadContext>::unavailable(
                    os_prov, "Thread register capture disabled by CaptureOptions.", ctx_stamp);
            }

            const std::uint64_t sp = effective_thread_sp(ts).value_or(0u);
            if (options.capture_thread_stacks && options.max_stack_bytes_per_thread > 0u && sp != 0u) {
                const std::uint64_t max_no_wrap = std::numeric_limits<std::uint64_t>::max() - sp;
                std::uint64_t req_bytes = std::min<std::uint64_t>(
                    static_cast<std::uint64_t>(options.max_stack_bytes_per_thread), max_no_wrap);
                for (const MemoryRegion& reg : regions_span) {
                    if (reg.contains(sp) && reg.end_address > sp) {
                        req_bytes = std::min<std::uint64_t>(req_bytes, reg.end_address - sp);
                        break;
                    }
                }
                if (req_bytes > 0u) {
                    ts.stack_capture_address = sp;
                    ts.stack_bytes = read_memory_tolerant(
                        session,
                        regions_span,
                        sp,
                        static_cast<std::size_t>(req_bytes));
                }
            }

            if (options.unwind_top_frames && options.max_unwind_frames > 0u &&
                ts.context.has_value() && !ts.context.is_unavailable()) {
                ThreadStackSnapshot unwound = unwind_and_inspect_stack(
                    session,
                    *ts.context.value,
                    regions_span,
                    modules_span,
                    nullptr,
                    {},
                    options.max_unwind_frames,
                    0u);
                ts.top_frames = std::move(unwound.frames);
            }

            thread_snaps.push_back(std::move(ts));
        }

        const CaptureAvailability th_avail =
            any_partial_thread_entry ? CaptureAvailability::Partial : CaptureAvailability::Complete;
        const CaptureStamp th_stamp = CaptureStamp::capture_now(
            snapshot.target_id, snapshot.snapshot_revision, paused, th_avail);
        if (th_avail == CaptureAvailability::Complete) {
            snapshot.threads = Observed<std::vector<ThreadSnapshot>>::complete(
                std::move(thread_snaps), os_prov, th_stamp);
        } else {
            snapshot.threads = Observed<std::vector<ThreadSnapshot>>::partial(
                std::move(thread_snaps),
                os_prov,
                "One or more thread entries reported partial metadata.",
                th_stamp);
        }
    } else {
        const CaptureStamp th_stamp = CaptureStamp::capture_now(
            snapshot.target_id, snapshot.snapshot_revision, paused, CaptureAvailability::Unavailable);
        snapshot.threads = Observed<std::vector<ThreadSnapshot>>::unavailable(
            os_prov, threads_res.error().message, th_stamp);
    }

    // 4. Handles, sockets & security profile
    if (options.capture_handles_and_sockets) {
        ProcessInternalsSnapshot internals = inspect_process_internals(session);

        const CaptureAvailability h_avail =
            map_subsystem_availability(internals.handles.status.availability);
        const CaptureStamp h_stamp = CaptureStamp::capture_now(
            snapshot.target_id, snapshot.snapshot_revision, paused, h_avail);
        snapshot.handles = Observed<std::vector<ProcessHandleEntry>>::from_forgiving(
            std::move(internals.handles), os_prov, h_stamp);

        const CaptureAvailability s_avail =
            map_subsystem_availability(internals.sockets.status.availability);
        const CaptureStamp s_stamp = CaptureStamp::capture_now(
            snapshot.target_id, snapshot.snapshot_revision, paused, s_avail);
        snapshot.sockets = Observed<std::vector<ProcessSocketEntry>>::from_forgiving(
            std::move(internals.sockets), os_prov, s_stamp);

        const CaptureAvailability sec_avail =
            map_subsystem_availability(internals.security.status.availability);
        const CaptureStamp sec_stamp = CaptureStamp::capture_now(
            snapshot.target_id, snapshot.snapshot_revision, paused, sec_avail);
        snapshot.security = Observed<ProcessSecurityProfile>::from_forgiving(
            std::move(internals.security), os_prov, sec_stamp);
    } else {
        const auto skipped_stamp = [&]() {
            return CaptureStamp::capture_now(
                snapshot.target_id,
                snapshot.snapshot_revision,
                paused,
                CaptureAvailability::Unavailable);
        };
        snapshot.handles = Observed<std::vector<ProcessHandleEntry>>::unavailable(
            os_prov, "Handle capture disabled by CaptureOptions.", skipped_stamp());
        snapshot.sockets = Observed<std::vector<ProcessSocketEntry>>::unavailable(
            os_prov, "Socket capture disabled by CaptureOptions.", skipped_stamp());
        snapshot.security = Observed<ProcessSecurityProfile>::unavailable(
            os_prov, "Security profile capture disabled by CaptureOptions.", skipped_stamp());
    }

    // 5. Launch / current environment settings (redacted by default)
    if (dynamic_cast<const IGdbRemoteSession*>(&session) != nullptr) {
        const CaptureStamp env_stamp = CaptureStamp::capture_now(
            snapshot.target_id, snapshot.snapshot_revision, paused, CaptureAvailability::Unavailable);
        snapshot.launch_environment = Observed<LaunchEnvironmentSettings>::unavailable(
            os_prov,
            "GDB RSP read-only session does not expose remote OS launch environment.",
            env_stamp);
    } else if (options.capture_environment) {
        RuntimeSettingsOptions rt_opts{};
        rt_opts.redaction_policy = options.environment_redaction_policy;
        rt_opts.launched_by_session = options.launched_by_session;
        rt_opts.query_process_internals = false;
        snapshot.launch_environment = extract_launch_environment_settings(
            session,
            snapshot.target_id,
            snapshot.snapshot_revision,
            rt_opts,
            &snapshot.security,
            nullptr);
    } else {
        const CaptureStamp env_stamp = CaptureStamp::capture_now(
            snapshot.target_id, snapshot.snapshot_revision, paused, CaptureAvailability::Unavailable);
        snapshot.launch_environment = Observed<LaunchEnvironmentSettings>::unavailable(
            os_prov, "Environment capture disabled by CaptureOptions.", env_stamp);
    }

    (void)mem_prov;
    return snapshot;
}

void populate_runtime_settings_from_snapshot(
    ExecutableSettingsReport& report,
    const ProcessStateSnapshot& snapshot,
    std::span<const std::uint64_t> timeline_proven_dynamic_bases) {
    report.launch_environment = snapshot.launch_environment;

    const ProvenanceTag prov =
        (snapshot.target_id.backend == BackendKind::CrashDumpMinidump ||
         snapshot.target_id.backend == BackendKind::CrashDumpElfCore)
            ? ProvenanceTag::CrashDump
            : ProvenanceTag::ProcOrOsApi;

    ObservedRuntimeConfiguration runtime{};
    runtime.loaded_modules = snapshot.modules;
    runtime.open_handles = snapshot.handles;
    runtime.sockets = snapshot.sockets;
    runtime.declared_vs_loaded = reconcile_declared_vs_loaded_modules(
        report.declared_in_file,
        snapshot.modules,
        snapshot.process_info.executable_path,
        timeline_proven_dynamic_bases);

    const bool any_available =
        !runtime.loaded_modules.is_unavailable() ||
        !runtime.open_handles.is_unavailable() ||
        !runtime.sockets.is_unavailable();

    if (!any_available) {
        report.observed_runtime = Observed<ObservedRuntimeConfiguration>::unavailable(
            prov,
            "All runtime collections (modules, handles, sockets) are unavailable in snapshot.",
            snapshot.snapshot_stamp);
        return;
    }

    const bool all_complete =
        runtime.loaded_modules.availability == CaptureAvailability::Complete &&
        runtime.open_handles.availability == CaptureAvailability::Complete &&
        runtime.sockets.availability == CaptureAvailability::Complete;

    CaptureStamp rt_stamp = snapshot.snapshot_stamp;
    rt_stamp.availability =
        all_complete ? CaptureAvailability::Complete : CaptureAvailability::Partial;

    if (all_complete) {
        report.observed_runtime = Observed<ObservedRuntimeConfiguration>::complete(
            std::move(runtime), prov, std::move(rt_stamp));
    } else {
        report.observed_runtime = Observed<ObservedRuntimeConfiguration>::partial(
            std::move(runtime),
            prov,
            "One or more observed runtime collections are partial or unavailable.",
            std::move(rt_stamp));
    }
}

SnapshotDiff diff_process_snapshots(
    const ProcessStateSnapshot& before,
    const ProcessStateSnapshot& after,
    const SnapshotDiffOptions& options) {
    SnapshotDiff diff{};
    diff.before_target_id = before.target_id;
    diff.after_target_id = after.target_id;
    diff.before_revision = before.snapshot_revision;
    diff.after_revision = after.snapshot_revision;
    diff.before_stamp = before.snapshot_stamp;
    diff.after_stamp = after.snapshot_stamp;

    diff.target_identity_matched = before.target_id.same_instance(after.target_id);
    if (!diff.target_identity_matched && !options.allow_cross_target) {
        diff.rejected_target_mismatch = true;
        SnapshotUncertainty unc{};
        unc.domain = DiffDomain::TargetIdentity;
        unc.kind = DiffUncertaintyKind::TargetIdentityMismatch;
        unc.before_availability = before.snapshot_stamp.availability;
        unc.after_availability = after.snapshot_stamp.availability;
        unc.message = std::format(
            "Target identity mismatch between snapshots (before PID={} creation={}, after PID={} creation={}); refusing to conflate distinct process instances (possible PID reuse).",
            before.target_id.pid,
            before.target_id.creation_identity.has_value()
                ? std::to_string(*before.target_id.creation_identity)
                : "n/a",
            after.target_id.pid,
            after.target_id.creation_identity.has_value()
                ? std::to_string(*after.target_id.creation_identity)
                : "n/a");
        diff.uncertainties.push_back(std::move(unc));
        diff.summary = "Snapshot diff aborted: target identity mismatch (PID reuse or distinct target).";
        return diff;
    }

    diff_modules(before, after, diff);
    diff_regions(before, after, options, diff);
    diff_threads(before, after, diff);
    diff_handles(before, after, diff);
    diff_sockets(before, after, diff);

    diff.summary = std::format(
        "Rev {} -> {}: {} module delta(s), {} region delta(s), {} thread delta(s), {} handle delta(s), {} socket delta(s), {} uncertainty note(s).",
        diff.before_revision,
        diff.after_revision,
        diff.modules.size(),
        diff.regions.size(),
        diff.threads.size(),
        diff.handles.size(),
        diff.sockets.size(),
        diff.uncertainties.size());
    return diff;
}

std::vector<std::uint64_t> collect_loaded_module_bases_from_diff(
    const SnapshotDiff& diff) {
    std::vector<std::uint64_t> bases;
    if (!diff.target_identity_matched || diff.rejected_target_mismatch) {
        return bases;
    }
    for (const ModuleDelta& md : diff.modules) {
        if (md.kind == ModuleDeltaKind::Loaded && md.after.has_value()) {
            const std::uint64_t base = md.after->base_address;
            if (std::ranges::find(bases, base) == bases.end()) {
                bases.push_back(base);
            }
        }
    }
    return bases;
}

}  // namespace peelf
