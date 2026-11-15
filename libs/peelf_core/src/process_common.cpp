#include "peelf/process.hpp"

#include <algorithm>
#include <array>
#include <cctype>
#include <charconv>
#include <fstream>
#include <limits>
#include <unordered_map>
#include <utility>

#ifdef __linux__
#include <unistd.h>
#elif defined(_WIN32)
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

[[nodiscard]] std::string_view trim_ascii(std::string_view s) noexcept {
    while (!s.empty() && (s.front() == ' ' || s.front() == '\t' || s.front() == '\r')) {
        s.remove_prefix(1);
    }
    while (!s.empty() && (s.back() == ' ' || s.back() == '\t' || s.back() == '\r')) {
        s.remove_suffix(1);
    }
    return s;
}

[[nodiscard]] std::optional<std::uint64_t> parse_hex_u64(std::string_view token) noexcept {
    if (token.empty()) {
        return std::nullopt;
    }
    std::uint64_t value = 0;
    const auto [ptr, ec] = std::from_chars(token.data(), token.data() + token.size(), value, 16);
    if (ec != std::errc{} || ptr != token.data() + token.size()) {
        return std::nullopt;
    }
    return value;
}

[[nodiscard]] std::string_view next_whitespace_token(std::string_view& rest) noexcept {
    while (!rest.empty() && (rest.front() == ' ' || rest.front() == '\t')) {
        rest.remove_prefix(1);
    }
    std::size_t pos = 0;
    while (pos < rest.size() && rest[pos] != ' ' && rest[pos] != '\t') {
        ++pos;
    }
    const std::string_view tok = rest.substr(0, pos);
    rest.remove_prefix(pos);
    return tok;
}

[[nodiscard]] bool iequals_ascii(std::string_view a, std::string_view b) noexcept {
    if (a.size() != b.size()) {
        return false;
    }
    for (std::size_t i = 0; i < a.size(); ++i) {
        if (std::tolower(static_cast<unsigned char>(a[i])) !=
            std::tolower(static_cast<unsigned char>(b[i]))) {
            return false;
        }
    }
    return true;
}

[[nodiscard]] bool looks_like_binary_module_filename(std::string_view filename) noexcept {
    if (filename.empty()) {
        return false;
    }
    if (filename.find(".so.") != std::string_view::npos) {
        return true;
    }
    const auto dot = filename.rfind('.');
    if (dot != std::string_view::npos) {
        const std::string_view ext = filename.substr(dot);
        if (iequals_ascii(ext, ".so") || iequals_ascii(ext, ".dll") ||
            iequals_ascii(ext, ".exe") || iequals_ascii(ext, ".elf") ||
            iequals_ascii(ext, ".pyd") || iequals_ascii(ext, ".drv") ||
            iequals_ascii(ext, ".ocx") || iequals_ascii(ext, ".sys")) {
            return true;
        }
    }
    return filename.starts_with("ld-linux") || filename.starts_with("ld-musl");
}

[[nodiscard]] std::string basename_from_path(std::string_view path_str) {
    const auto slash = path_str.find_last_of("/\\");
    if (slash == std::string_view::npos) {
        return std::string(path_str);
    }
    return std::string(path_str.substr(slash + 1));
}

[[nodiscard]] MemoryRegionKind classify_initial_region_kind(std::string_view pathname,
                                                            std::string_view clean_main_exe) {
    if (pathname.empty() || pathname.starts_with("[anon")) {
        return MemoryRegionKind::Anonymous;
    }
    if (pathname == "[heap]" || pathname.starts_with("[heap:")) {
        return MemoryRegionKind::Heap;
    }
    if (pathname == "[stack]" || pathname.starts_with("[stack:")) {
        return MemoryRegionKind::Stack;
    }
    if (pathname == "[vdso]" || pathname == "[vvar]" || pathname == "[vsyscall]" ||
        pathname.starts_with("[vvar")) {
        return MemoryRegionKind::Vdso;
    }
    if (pathname.front() == '[') {
        return MemoryRegionKind::Anonymous;
    }
    const std::string clean = strip_deleted_proc_suffix(pathname);
    if (!clean_main_exe.empty() && clean == clean_main_exe) {
        return MemoryRegionKind::Image;
    }
    return MemoryRegionKind::MappedFile;
}

[[nodiscard]] std::optional<std::vector<std::uint8_t>> try_read_disk_file(
    const std::filesystem::path& path,
    std::size_t max_bytes = 256ull * 1024ull * 1024ull) {
    std::error_code ec;
    if (path.empty() || !std::filesystem::is_regular_file(path, ec) || ec) {
        return std::nullopt;
    }
    const auto file_sz = std::filesystem::file_size(path, ec);
    if (ec || file_sz == 0 || file_sz > max_bytes) {
        return std::nullopt;
    }
    std::ifstream in(path, std::ios::binary);
    if (!in) {
        return std::nullopt;
    }
    std::vector<std::uint8_t> bytes(static_cast<std::size_t>(file_sz));
    in.read(reinterpret_cast<char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
    if (in.gcount() != static_cast<std::streamsize>(bytes.size())) {
        return std::nullopt;
    }
    return bytes;
}

void probe_module_format_and_entry(ModuleInfo& mod, IProcessSession* probe_session) {
    if (probe_session != nullptr) {
        std::array<std::uint8_t, 512> header{};
        auto read_res = probe_session->read_memory(mod.base_address, header);
        if (read_res && *read_res >= 4) {
            const auto span = std::span<const std::uint8_t>(header.data(), *read_res);
            mod.format = detect_format(span);
            if (mod.format == Format::ELF && *read_res >= 64) {
                const bool is_64 = header[4] == 2;
                const bool le = header[5] != 2;
                const auto rd16 = [&](std::size_t off) -> std::uint16_t {
                    return le ? static_cast<std::uint16_t>(header[off] | (header[off + 1] << 8))
                              : static_cast<std::uint16_t>((header[off] << 8) | header[off + 1]);
                };
                const auto rd32 = [&](std::size_t off) -> std::uint32_t {
                    std::uint32_t v = 0;
                    for (std::size_t i = 0; i < 4; ++i) {
                        const std::size_t idx = le ? (off + i) : (off + 3 - i);
                        v |= static_cast<std::uint32_t>(header[idx]) << (8 * i);
                    }
                    return v;
                };
                const auto rd64 = [&](std::size_t off) -> std::uint64_t {
                    std::uint64_t v = 0;
                    for (std::size_t i = 0; i < 8; ++i) {
                        const std::size_t idx = le ? (off + i) : (off + 7 - i);
                        v |= static_cast<std::uint64_t>(header[idx]) << (8 * i);
                    }
                    return v;
                };
                const std::uint16_t e_type = rd16(16);
                const std::uint64_t e_entry = is_64 ? rd64(24) : static_cast<std::uint64_t>(rd32(24));
                if (e_entry != 0) {
                    if (e_type == 3 && e_entry < mod.size) {
                        mod.entry_point = mod.base_address + e_entry;
                    } else {
                        mod.entry_point = e_entry;
                    }
                }
            } else if (mod.format == Format::PE && *read_res >= 0x40) {
                const std::uint32_t lfanew =
                    static_cast<std::uint32_t>(header[0x3C]) |
                    (static_cast<std::uint32_t>(header[0x3D]) << 8) |
                    (static_cast<std::uint32_t>(header[0x3E]) << 16) |
                    (static_cast<std::uint32_t>(header[0x3F]) << 24);
                if (static_cast<std::size_t>(lfanew) + 44 <= *read_res &&
                    header[lfanew] == 'P' && header[lfanew + 1] == 'E' &&
                    header[lfanew + 2] == 0 && header[lfanew + 3] == 0) {
                    const std::size_t opt = static_cast<std::size_t>(lfanew) + 24;
                    const std::uint32_t entry_rva =
                        static_cast<std::uint32_t>(header[opt + 16]) |
                        (static_cast<std::uint32_t>(header[opt + 17]) << 8) |
                        (static_cast<std::uint32_t>(header[opt + 18]) << 16) |
                        (static_cast<std::uint32_t>(header[opt + 19]) << 24);
                    if (entry_rva != 0) {
                        mod.entry_point = mod.base_address + entry_rva;
                    }
                }
            }
        }
    }

    if (mod.format == Format::Unknown && !mod.path.empty()) {
        std::error_code ec;
        if (std::filesystem::is_regular_file(mod.path, ec) && !ec) {
            std::ifstream in(mod.path, std::ios::binary);
            std::array<std::uint8_t, 4> magic{};
            if (in.read(reinterpret_cast<char*>(magic.data()), 4)) {
                mod.format = detect_format(magic);
            }
        }
    }
}

}  // namespace

ProcessId current_process_id() noexcept {
#ifdef __linux__
    return static_cast<ProcessId>(::getpid());
#elif defined(_WIN32)
    return static_cast<ProcessId>(::GetCurrentProcessId());
#else
    return 0;
#endif
}

std::string strip_deleted_proc_suffix(std::string_view pathname) {
    constexpr std::string_view kDeleted = " (deleted)";
    if (pathname.ends_with(kDeleted)) {
        pathname.remove_suffix(kDeleted.size());
    }
    return std::string(pathname);
}

Result<std::vector<MemoryRegion>> parse_proc_maps(std::string_view maps_text,
                                                  std::string_view main_exe_path) {
    const std::string clean_main = strip_deleted_proc_suffix(trim_ascii(main_exe_path));
    std::vector<MemoryRegion> regions;

    std::size_t pos = 0;
    while (pos < maps_text.size()) {
        const std::size_t nl = maps_text.find('\n', pos);
        std::string_view line =
            (nl == std::string_view::npos) ? maps_text.substr(pos) : maps_text.substr(pos, nl - pos);
        pos = (nl == std::string_view::npos) ? maps_text.size() : (nl + 1);

        line = trim_ascii(line);
        if (line.empty()) {
            continue;
        }

        std::string_view cursor = line;
        const std::string_view range_tok = next_whitespace_token(cursor);
        const std::string_view perms_tok = next_whitespace_token(cursor);
        const std::string_view offset_tok = next_whitespace_token(cursor);
        const std::string_view dev_tok = next_whitespace_token(cursor);
        const std::string_view inode_tok = next_whitespace_token(cursor);
        (void)dev_tok;
        (void)inode_tok;

        const std::size_t dash = range_tok.find('-');
        if (dash == std::string_view::npos || perms_tok.size() < 4 || offset_tok.empty()) {
            return make_error("malformed /proc/maps entry");
        }

        const auto start = parse_hex_u64(range_tok.substr(0, dash));
        const auto end = parse_hex_u64(range_tok.substr(dash + 1));
        const auto file_off = parse_hex_u64(offset_tok);
        if (!start || !end || !file_off || *end < *start) {
            return make_error("invalid address or offset in /proc/maps entry");
        }

        const std::string_view path_view = trim_ascii(cursor);

        MemoryRegion region;
        region.start_address = *start;
        region.end_address = *end;
        region.protection.readable = perms_tok[0] == 'r';
        region.protection.writable = perms_tok[1] == 'w';
        region.protection.executable = perms_tok[2] == 'x';
        region.protection.shared = perms_tok[3] == 's';
        region.file_offset = *file_off;
        region.pathname = std::string(path_view);
        region.kind = classify_initial_region_kind(region.pathname, clean_main);

        regions.push_back(std::move(region));
    }

    return regions;
}

std::vector<ModuleInfo> derive_modules_from_regions(std::vector<MemoryRegion>& regions,
                                                    std::string_view main_exe_path,
                                                    IProcessSession* probe_session) {
    const std::string clean_main = strip_deleted_proc_suffix(trim_ascii(main_exe_path));

    struct Group {
        std::string clean_path;
        std::vector<std::size_t> region_indices;
        bool has_exec{false};
        bool is_vdso{false};
    };

    std::vector<Group> groups;
    std::unordered_map<std::string, std::size_t> group_by_path;

    for (std::size_t i = 0; i < regions.size(); ++i) {
        const MemoryRegion& reg = regions[i];
        if (reg.pathname.empty()) {
            continue;
        }
        if (reg.pathname == "[vdso]") {
            Group g;
            g.clean_path = "[vdso]";
            g.region_indices.push_back(i);
            g.has_exec = reg.protection.executable;
            g.is_vdso = true;
            groups.push_back(std::move(g));
            continue;
        }
        if (reg.pathname.front() == '[' || reg.pathname.starts_with("/dev/")) {
            continue;
        }

        const std::string clean = strip_deleted_proc_suffix(reg.pathname);
        auto [it, inserted] = group_by_path.emplace(clean, groups.size());
        if (inserted) {
            Group g;
            g.clean_path = clean;
            groups.push_back(std::move(g));
        }
        Group& grp = groups[it->second];
        grp.region_indices.push_back(i);
        if (reg.protection.executable) {
            grp.has_exec = true;
        }
    }

    std::vector<ModuleInfo> modules;
    for (const Group& grp : groups) {
        if (grp.region_indices.empty()) {
            continue;
        }

        if (grp.is_vdso) {
            const MemoryRegion& vdso_reg = regions[grp.region_indices.front()];
            bool magic_ok = false;
            if (probe_session != nullptr && vdso_reg.protection.readable) {
                std::array<std::uint8_t, 4> magic{};
                auto res = probe_session->read_memory(vdso_reg.start_address, magic);
                magic_ok = res && *res == 4 && detect_format(magic) == Format::ELF;
            }
            if (!magic_ok && !grp.has_exec) {
                continue;
            }
            ModuleInfo mod;
            mod.name = "[vdso]";
            mod.base_address = vdso_reg.start_address;
            mod.size = vdso_reg.size();
            mod.format = Format::ELF;
            probe_module_format_and_entry(mod, probe_session);
            regions[grp.region_indices.front()].module_name = mod.name;
            modules.push_back(std::move(mod));
            continue;
        }

        const std::string short_name = basename_from_path(grp.clean_path);
        const bool is_main = !clean_main.empty() && grp.clean_path == clean_main;
        bool is_module = is_main || grp.has_exec || looks_like_binary_module_filename(short_name);

        const std::uint64_t first_start = regions[grp.region_indices.front()].start_address;
        if (!is_module && probe_session != nullptr &&
            regions[grp.region_indices.front()].protection.readable) {
            std::array<std::uint8_t, 4> magic{};
            auto res = probe_session->read_memory(first_start, magic);
            if (res && *res == 4 && detect_format(magic) != Format::Unknown) {
                is_module = true;
            }
        }

        if (!is_module) {
            continue;
        }

        std::uint64_t min_addr = first_start;
        std::uint64_t max_addr = regions[grp.region_indices.front()].end_address;
        for (const std::size_t idx : grp.region_indices) {
            min_addr = std::min(min_addr, regions[idx].start_address);
            max_addr = std::max(max_addr, regions[idx].end_address);
            regions[idx].kind = MemoryRegionKind::Image;
            regions[idx].module_name = short_name;
        }

        // Include immediately adjacent anonymous rw-p zero-fill (.bss) tail if present.
        const std::size_t last_idx = grp.region_indices.back();
        if (last_idx + 1 < regions.size()) {
            MemoryRegion& tail = regions[last_idx + 1];
            if (tail.pathname.empty() && tail.start_address == max_addr &&
                tail.protection.readable && tail.protection.writable && !tail.protection.executable) {
                max_addr = tail.end_address;
                tail.module_name = short_name;
            }
        }

        ModuleInfo mod;
        mod.name = short_name;
        mod.path = std::filesystem::path(grp.clean_path);
        mod.base_address = min_addr;
        mod.size = max_addr >= min_addr ? (max_addr - min_addr) : 0;
        mod.is_main_module = is_main;
        probe_module_format_and_entry(mod, probe_session);
        modules.push_back(std::move(mod));
    }

    if (!modules.empty() &&
        std::ranges::none_of(modules, [](const ModuleInfo& m) { return m.is_main_module; })) {
        // Fallback: mark the first non-vdso executable image (lowest non-library or first image)
        // when /proc/<pid>/exe was unreadable.
        for (ModuleInfo& mod : modules) {
            if (mod.name != "[vdso]" && !looks_like_binary_module_filename(mod.name)) {
                mod.is_main_module = true;
                break;
            }
        }
    }

    std::ranges::sort(modules, [](const ModuleInfo& lhs, const ModuleInfo& rhs) {
        if (lhs.is_main_module != rhs.is_main_module) {
            return lhs.is_main_module;
        }
        return lhs.base_address < rhs.base_address;
    });

    return modules;
}

MemorySample read_memory_tolerant(IProcessSession& session,
                                  std::span<const MemoryRegion> regions,
                                  std::uint64_t address,
                                  std::size_t size) {
    MemorySample sample;
    sample.bytes.assign(size, 0);
    sample.valid.assign(size, 0);
    if (size == 0) {
        return sample;
    }

    constexpr std::size_t kMaxChunk = 65536;
    constexpr std::uint64_t kPageSize = 4096;

    const auto read_chunk_with_page_fallback = [&](std::size_t rel_offset, std::size_t len) {
        const std::uint64_t chunk_va = address + static_cast<std::uint64_t>(rel_offset);
        auto out_span = std::span<std::uint8_t>(sample.bytes.data() + rel_offset, len);
        auto fast = session.read_memory(chunk_va, out_span);
        if (fast && *fast == len) {
            std::fill_n(sample.valid.data() + rel_offset, len, static_cast<std::uint8_t>(1));
            sample.readable_count += len;
            return;
        }

        std::size_t cursor = 0;
        if (fast && *fast > 0 && *fast < len) {
            std::fill_n(sample.valid.data() + rel_offset, *fast, static_cast<std::uint8_t>(1));
            sample.readable_count += *fast;
            cursor = *fast;
        }

        while (cursor < len) {
            const std::uint64_t page_va = chunk_va + static_cast<std::uint64_t>(cursor);
            const std::uint64_t page_rem = kPageSize - (page_va % kPageSize);
            const std::size_t step = static_cast<std::size_t>(
                std::min<std::uint64_t>(page_rem, static_cast<std::uint64_t>(len - cursor)));
            auto page_span =
                std::span<std::uint8_t>(sample.bytes.data() + rel_offset + cursor, step);
            auto page_res = session.read_memory(page_va, page_span);
            if (page_res && *page_res > 0) {
                const std::size_t got = std::min(*page_res, step);
                std::fill_n(sample.valid.data() + rel_offset + cursor,
                            got,
                            static_cast<std::uint8_t>(1));
                sample.readable_count += got;
                if (got < step) {
                    std::fill_n(sample.bytes.data() + rel_offset + cursor + got,
                                step - got,
                                static_cast<std::uint8_t>(0));
                }
            } else {
                std::fill_n(sample.bytes.data() + rel_offset + cursor,
                            step,
                            static_cast<std::uint8_t>(0));
            }
            cursor += step;
        }
    };

    if (regions.empty()) {
        std::size_t offset = 0;
        while (offset < size) {
            const std::size_t step = std::min(kMaxChunk, size - offset);
            read_chunk_with_page_fallback(offset, step);
            offset += step;
        }
        return sample;
    }

    const std::uint64_t end_address =
        (address > std::numeric_limits<std::uint64_t>::max() - static_cast<std::uint64_t>(size))
            ? std::numeric_limits<std::uint64_t>::max()
            : (address + static_cast<std::uint64_t>(size));

    for (const MemoryRegion& reg : regions) {
        if (reg.end_address <= address || reg.start_address >= end_address) {
            continue;
        }
        if (!reg.protection.readable || reg.protection.guarded) {
            continue;
        }
        const std::uint64_t overlap_begin = std::max(address, reg.start_address);
        const std::uint64_t overlap_end = std::min(end_address, reg.end_address);
        std::size_t rel = static_cast<std::size_t>(overlap_begin - address);
        std::size_t rem = static_cast<std::size_t>(overlap_end - overlap_begin);
        while (rem > 0) {
            const std::size_t step = std::min(kMaxChunk, rem);
            read_chunk_with_page_fallback(rel, step);
            rel += step;
            rem -= step;
        }
    }

    return sample;
}

Result<std::unique_ptr<IBinaryImage>> load_live_module_image(
    IProcessSession& session,
    const ModuleInfo& module,
    std::span<const MemoryRegion> regions) {
    if (module.base_address == 0 && module.size == 0) {
        return make_error("invalid module base address and size");
    }

    // Prefer on-disk backing PE/ELF when readable so unmapped sections (such as ELF
    // .symtab/.strtab) and original import lookup tables are preserved and rebased to
    // the module's live runtime base.
    if (auto disk_bytes = try_read_disk_file(module.path)) {
        auto rebased = parse_rebased_image(*disk_bytes, module.base_address);
        if (rebased) {
            return rebased;
        }
    }

    constexpr std::uint64_t kMaxSnapshotBytes = 64ull * 1024ull * 1024ull;
    constexpr std::uint64_t kDefaultProbeSize = 64ull * 1024ull;
    const std::size_t snapshot_size = static_cast<std::size_t>(
        std::min<std::uint64_t>(module.size > 0 ? module.size : kDefaultProbeSize, kMaxSnapshotBytes));

    MemorySample sample =
        read_memory_tolerant(session, regions, module.base_address, snapshot_size);
    if (sample.readable_count == 0) {
        return make_error("failed to read mapped module bytes from process memory");
    }

    return parse_mapped_image(sample.bytes, module.base_address);
}

#if !defined(__linux__) && !defined(_WIN32)
namespace {
class UnsupportedProcessBackend final : public IProcessBackend {
public:
    Result<std::vector<ProcessInfo>> list_processes() override {
        return make_error("live process exploration is not supported on this platform");
    }
    Result<std::unique_ptr<IProcessSession>> open_process(ProcessId) override {
        return make_error("live process exploration is not supported on this platform");
    }
};
}  // namespace

std::shared_ptr<IProcessBackend> create_native_process_backend() {
    return std::make_shared<UnsupportedProcessBackend>();
}
#endif

}  // namespace peelf
