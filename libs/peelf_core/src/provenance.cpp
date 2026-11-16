#include <peelf/provenance.hpp>

#include <peelf/sha256.hpp>

#include <algorithm>
#include <array>
#include <charconv>
#include <chrono>
#include <cstdint>
#include <ctime>
#include <format>
#include <fstream>
#include <sstream>
#include <string>
#include <string_view>

#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#endif

namespace peelf {
namespace {

[[nodiscard]] std::string bytes_to_lower_hex(std::span<const std::uint8_t> bytes) {
    std::string out;
    out.reserve(bytes.size() * 2u);
    for (const std::uint8_t b : bytes) {
        out += std::format("{:02x}", static_cast<unsigned int>(b));
    }
    return out;
}

} // namespace

std::string format_utc_iso8601_ms(std::uint64_t unix_epoch_ms) {
    const auto whole_seconds = static_cast<std::time_t>(unix_epoch_ms / 1000ull);
    const auto millis = static_cast<unsigned int>(unix_epoch_ms % 1000ull);

    std::tm utc_tm{};
#ifdef _WIN32
    if (::gmtime_s(&utc_tm, &whole_seconds) != 0) {
        return "1970-01-01T00:00:00.000Z";
    }
#else
    if (::gmtime_r(&whole_seconds, &utc_tm) == nullptr) {
        return "1970-01-01T00:00:00.000Z";
    }
#endif

    return std::format("{:04d}-{:02d}-{:02d}T{:02d}:{:02d}:{:02d}.{:03d}Z",
                       utc_tm.tm_year + 1900,
                       utc_tm.tm_mon + 1,
                       utc_tm.tm_mday,
                       utc_tm.tm_hour,
                       utc_tm.tm_min,
                       utc_tm.tm_sec,
                       millis);
}

CaptureStamp CaptureStamp::capture_now(
    const TargetInstanceId& target,
    std::uint64_t revision,
    bool paused,
    CaptureAvailability avail) {
    const auto sys_now = std::chrono::system_clock::now();
    const auto steady_now = std::chrono::steady_clock::now();

    const auto unix_ms = static_cast<std::uint64_t>(
        std::max<std::int64_t>(
            0,
            std::chrono::duration_cast<std::chrono::milliseconds>(
                sys_now.time_since_epoch())
                .count()));
    const auto mono_ns = static_cast<std::uint64_t>(
        std::max<std::int64_t>(
            0,
            std::chrono::duration_cast<std::chrono::nanoseconds>(
                steady_now.time_since_epoch())
                .count()));

    CaptureStamp stamp;
    stamp.target_id = target;
    stamp.snapshot_revision = revision;
    stamp.captured_unix_ms = unix_ms;
    stamp.captured_at_utc = format_utc_iso8601_ms(unix_ms);
    stamp.monotonic_ns = mono_ns;
    stamp.target_paused = paused;
    stamp.availability = avail;
    return stamp;
}

std::optional<std::uint64_t> parse_linux_proc_stat_starttime(
    std::string_view proc_stat_line) noexcept {
    // Format: `<pid> (<comm>) <state> <ppid> ...` where `<comm>` can contain spaces or `)`.
    // Locate the LAST `)` on the line; field 3 (`state`) starts immediately after `) `.
    const std::size_t rparen = proc_stat_line.rfind(')');
    if (rparen == std::string_view::npos || rparen + 2u >= proc_stat_line.size()) {
        return std::nullopt;
    }

    std::string_view rest = proc_stat_line.substr(rparen + 1u);
    // Field 1 = pid, Field 2 = (comm), so tokens in `rest` start at Field 3 (`state`).
    // Field 22 (`starttime`) is the 20th whitespace-separated token in `rest`.
    std::size_t field_num = 3u;
    while (!rest.empty()) {
        while (!rest.empty() &&
               (rest.front() == ' ' || rest.front() == '\t' || rest.front() == '\n' || rest.front() == '\r')) {
            rest.remove_prefix(1u);
        }
        if (rest.empty()) {
            break;
        }
        std::size_t tok_len = 0u;
        while (tok_len < rest.size() &&
               rest[tok_len] != ' ' && rest[tok_len] != '\t' &&
               rest[tok_len] != '\n' && rest[tok_len] != '\r') {
            ++tok_len;
        }
        const std::string_view tok = rest.substr(0u, tok_len);
        rest.remove_prefix(tok_len);

        if (field_num == 22u) {
            std::uint64_t ticks = 0u;
            const auto [ptr, ec] = std::from_chars(tok.data(), tok.data() + tok.size(), ticks, 10);
            if (ec == std::errc{} && ptr == tok.data() + tok.size()) {
                return ticks;
            }
            return std::nullopt;
        }
        ++field_num;
    }
    return std::nullopt;
}

std::optional<std::uint64_t> query_process_creation_identity(ProcessId pid) noexcept {
    if (pid == 0u) {
        return std::nullopt;
    }
#ifdef __linux__
    try {
        std::ifstream ifs(std::format("/proc/{}/stat", pid));
        if (!ifs) {
            return std::nullopt;
        }
        std::string line;
        std::getline(ifs, line);
        return parse_linux_proc_stat_starttime(line);
    } catch (...) {
        return std::nullopt;
    }
#elif defined(_WIN32)
    struct ScopedWinHandle {
        HANDLE handle{nullptr};
        explicit ScopedWinHandle(HANDLE h) noexcept : handle(h) {}
        ~ScopedWinHandle() noexcept {
            if (handle != nullptr && handle != INVALID_HANDLE_VALUE) {
                ::CloseHandle(handle);
            }
        }
        ScopedWinHandle(const ScopedWinHandle&) = delete;
        ScopedWinHandle& operator=(const ScopedWinHandle&) = delete;
    };
    const ScopedWinHandle proc(
        ::OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, static_cast<DWORD>(pid)));
    if (proc.handle == nullptr || proc.handle == INVALID_HANDLE_VALUE) {
        return std::nullopt;
    }
    FILETIME creation_ft{};
    FILETIME exit_ft{};
    FILETIME kernel_ft{};
    FILETIME user_ft{};
    const BOOL ok = ::GetProcessTimes(proc.handle, &creation_ft, &exit_ft, &kernel_ft, &user_ft);
    if (!ok) {
        return std::nullopt;
    }
    const std::uint64_t ticks =
        (static_cast<std::uint64_t>(creation_ft.dwHighDateTime) << 32u) |
        static_cast<std::uint64_t>(creation_ft.dwLowDateTime);
    return ticks != 0u ? std::optional<std::uint64_t>(ticks) : std::nullopt;
#else
    return std::nullopt;
#endif
}

std::string BackingImageIdentity::primary_identifier() const {
    if (!elf_build_id_hex.empty()) {
        return std::format("build-id:{}", elf_build_id_hex);
    }
    if (!codeview_guid_hex.empty()) {
        return std::format("rsds:{}:{}", codeview_guid_hex, codeview_age.value_or(0u));
    }
    if (pe_time_date_stamp.has_value() && pe_size_of_image.has_value()) {
        return std::format("pe-ts:{:08x}-sz:{:08x}", *pe_time_date_stamp, *pe_size_of_image);
    }
    if (!file_sha256.empty()) {
        return std::format("sha256:{}", file_sha256.substr(0u, 16u));
    }
    return {};
}

BackingImageIdentity extract_backing_image_identity(
    const IBinaryImage& image,
    std::span<const std::uint8_t> raw_file_bytes) {
    BackingImageIdentity id;
    id.format = image.format();
    id.architecture = image.architecture();
    id.address_width = image.is_64bit() ? AddressWidth::Bits64 : AddressWidth::Bits32;
    id.endianness = image.endianness();

    if (!raw_file_bytes.empty()) {
        id.file_sha256 = sha256_hex(raw_file_bytes);
    }

    if (image.format() == Format::PE) {
        if (const PeHeader* hdr = image.pe_header(); hdr != nullptr) {
            id.pe_time_date_stamp = hdr->time_date_stamp;
            id.pe_size_of_image = hdr->size_of_image;
            id.pe_checksum = hdr->checksum;
        }
        for (const PeDebugDirectory& dbg : image.pe_debug_directories()) {
            // IMAGE_DEBUG_TYPE_CODEVIEW == 2, 'RSDS' == 0x53445352
            if (dbg.type == 2u && !dbg.codeview_guid.empty()) {
                id.codeview_guid_hex = bytes_to_lower_hex(dbg.codeview_guid);
                id.codeview_age = dbg.codeview_age;
                break;
            }
        }
    } else if (image.format() == Format::ELF) {
        for (const ElfNote& note : image.elf_notes()) {
            // NT_GNU_BUILD_ID == 3, owner == "GNU"
            if (note.type == 3u &&
                (note.name == "GNU" || note.name.starts_with("GNU")) &&
                !note.descriptor.empty()) {
                id.elf_build_id_hex = bytes_to_lower_hex(note.descriptor);
                break;
            }
        }
        if (const GnuDebugLink* dlink = image.gnu_debuglink(); dlink != nullptr) {
            id.elf_gnu_debuglink_crc32 = dlink->crc32;
        }
    }

    return id;
}

BackingIdentityMatchResult verify_backing_image_identity(
    const BackingImageIdentity& disk_identity,
    const BackingImageIdentity& live_identity) {
    BackingIdentityMatchResult out;
    out.disk_identifier = disk_identity.primary_identifier();
    out.live_identifier = live_identity.primary_identifier();

    if (disk_identity.format == Format::Unknown || live_identity.format == Format::Unknown) {
        out.comparable = false;
        out.matches = true;
        out.summary = "Backing image identity could not be compared (unparsed format)";
        return out;
    }

    if (disk_identity.format != live_identity.format) {
        out.comparable = true;
        out.matches = false;
        out.mismatches.push_back(std::format(
            "Container format mismatch: disk={} vs live={}",
            to_string(disk_identity.format),
            to_string(live_identity.format)));
    }
    if (disk_identity.architecture != live_identity.architecture) {
        out.comparable = true;
        out.matches = false;
        out.mismatches.push_back(std::format(
            "Architecture mismatch: disk={} vs live={}",
            to_string(disk_identity.architecture),
            to_string(live_identity.architecture)));
    }
    if (disk_identity.address_width != live_identity.address_width) {
        out.comparable = true;
        out.matches = false;
        out.mismatches.push_back(std::format(
            "Address width mismatch: disk={} vs live={}",
            to_string(disk_identity.address_width),
            to_string(live_identity.address_width)));
    }

    if (disk_identity.format == Format::ELF && live_identity.format == Format::ELF) {
        if (!disk_identity.elf_build_id_hex.empty() && !live_identity.elf_build_id_hex.empty()) {
            out.comparable = true;
            if (disk_identity.elf_build_id_hex != live_identity.elf_build_id_hex) {
                out.matches = false;
                out.mismatches.push_back(std::format(
                    "ELF .note.gnu.build-id mismatch: disk={} vs live={}",
                    disk_identity.elf_build_id_hex,
                    live_identity.elf_build_id_hex));
            }
        }
    } else if (disk_identity.format == Format::PE && live_identity.format == Format::PE) {
        if (!disk_identity.codeview_guid_hex.empty() && !live_identity.codeview_guid_hex.empty()) {
            out.comparable = true;
            if (disk_identity.codeview_guid_hex != live_identity.codeview_guid_hex ||
                disk_identity.codeview_age != live_identity.codeview_age) {
                out.matches = false;
                out.mismatches.push_back(std::format(
                    "PE CodeView RSDS mismatch: disk={}:{} vs live={}:{}",
                    disk_identity.codeview_guid_hex,
                    disk_identity.codeview_age.value_or(0u),
                    live_identity.codeview_guid_hex,
                    live_identity.codeview_age.value_or(0u)));
            }
        }
        if (disk_identity.pe_time_date_stamp.has_value() &&
            live_identity.pe_time_date_stamp.has_value()) {
            out.comparable = true;
            if (*disk_identity.pe_time_date_stamp != *live_identity.pe_time_date_stamp) {
                out.matches = false;
                out.mismatches.push_back(std::format(
                    "PE TimeDateStamp mismatch: disk=0x{:08X} vs live=0x{:08X}",
                    *disk_identity.pe_time_date_stamp,
                    *live_identity.pe_time_date_stamp));
            }
        }
        if (disk_identity.pe_size_of_image.has_value() &&
            live_identity.pe_size_of_image.has_value()) {
            out.comparable = true;
            if (*disk_identity.pe_size_of_image != *live_identity.pe_size_of_image) {
                out.matches = false;
                out.mismatches.push_back(std::format(
                    "PE SizeOfImage mismatch: disk=0x{:X} vs live=0x{:X}",
                    *disk_identity.pe_size_of_image,
                    *live_identity.pe_size_of_image));
            }
        }
    }

    if (!out.comparable) {
        out.summary = "No strong build identifier (.note.gnu.build-id / RSDS / PE header) present in both disk and live images";
    } else if (out.matches) {
        out.summary = std::format("Backing image identity verified ({})",
                                  out.live_identifier.empty() ? "headers match" : out.live_identifier);
    } else {
        out.summary = out.mismatches.front();
    }

    return out;
}

BackingIdentityMatchResult verify_live_module_backing_identity(
    const IBinaryImage& disk_image,
    std::span<const std::uint8_t> disk_file_bytes,
    IProcessSession& session,
    const ModuleInfo& live_module,
    std::span<const MemoryRegion> regions) {
    const BackingImageIdentity disk_id =
        extract_backing_image_identity(disk_image, disk_file_bytes);

    if (live_module.base_address == 0u) {
        BackingIdentityMatchResult unavail;
        unavail.comparable = false;
        unavail.matches = true;
        unavail.disk_identifier = disk_id.primary_identifier();
        unavail.summary = "Live module base address is zero";
        return unavail;
    }

    constexpr std::uint64_t kMaxIdentityProbeBytes = 4ull * 1024ull * 1024ull;
    constexpr std::uint64_t kDefaultProbeBytes = 64ull * 1024ull;
    const auto probe_len = static_cast<std::size_t>(std::min<std::uint64_t>(
        live_module.size > 0u ? live_module.size : kDefaultProbeBytes,
        kMaxIdentityProbeBytes));

    const MemorySample sample =
        read_memory_tolerant(session, regions, live_module.base_address, probe_len);
    if (sample.readable_count < 64u) {
        BackingIdentityMatchResult unavail;
        unavail.comparable = false;
        unavail.matches = true;
        unavail.disk_identifier = disk_id.primary_identifier();
        unavail.summary = "Live module header pages are unreadable in target memory";
        return unavail;
    }

    auto live_parsed = parse_mapped_image(sample.bytes, live_module.base_address);
    if (!live_parsed.has_value()) {
        BackingIdentityMatchResult unavail;
        unavail.comparable = false;
        unavail.matches = true;
        unavail.disk_identifier = disk_id.primary_identifier();
        unavail.summary = "Live module memory could not be parsed as a PE/ELF header";
        return unavail;
    }

    const BackingImageIdentity live_id = extract_backing_image_identity(**live_parsed);
    return verify_backing_image_identity(disk_id, live_id);
}

} // namespace peelf
