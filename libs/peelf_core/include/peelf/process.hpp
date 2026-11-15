#pragma once

#include <peelf/binary_image.hpp>
#include <peelf/error.hpp>

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace peelf {

using ProcessId = std::uint32_t;

enum class ProcessAccessStatus : std::uint8_t {
    Accessible,
    ReadOnly,
    AccessDenied,
    Exited,
    Unknown,
};

[[nodiscard]] constexpr std::string_view to_string(ProcessAccessStatus status) noexcept {
    switch (status) {
        case ProcessAccessStatus::Accessible:   return "Accessible";
        case ProcessAccessStatus::ReadOnly:     return "ReadOnly";
        case ProcessAccessStatus::AccessDenied: return "AccessDenied";
        case ProcessAccessStatus::Exited:       return "Exited";
        case ProcessAccessStatus::Unknown:      return "Unknown";
    }
    return "Unknown";
}

struct ProcessInfo {
    ProcessId pid{0};
    ProcessId parent_pid{0};
    std::string name;
    std::filesystem::path executable_path;
    std::string command_line;
    std::string user;
    std::optional<std::uint32_t> uid;
    Architecture architecture{Architecture::Unknown};
    bool is_64bit{true};
    ProcessAccessStatus access{ProcessAccessStatus::Unknown};

    auto operator<=>(const ProcessInfo&) const = default;
};

struct MemoryProtection {
    bool readable{false};
    bool writable{false};
    bool executable{false};
    bool shared{false};
    bool guarded{false};

    [[nodiscard]] std::string to_short_string() const {
        std::string out(4, '-');
        if (readable) {
            out[0] = 'r';
        }
        if (writable) {
            out[1] = 'w';
        }
        if (executable) {
            out[2] = 'x';
        }
        out[3] = shared ? 's' : 'p';
        if (guarded) {
            out += "+g";
        }
        return out;
    }

    auto operator<=>(const MemoryProtection&) const = default;
};

[[nodiscard]] inline std::string format_protection(const MemoryProtection& protection) {
    return protection.to_short_string();
}

enum class MemoryRegionKind : std::uint8_t {
    Image,
    Heap,
    Stack,
    Vdso,
    MappedFile,
    Anonymous,
    Unknown,
};

[[nodiscard]] constexpr std::string_view to_string(MemoryRegionKind kind) noexcept {
    switch (kind) {
        case MemoryRegionKind::Image:      return "Image";
        case MemoryRegionKind::Heap:       return "Heap";
        case MemoryRegionKind::Stack:      return "Stack";
        case MemoryRegionKind::Vdso:       return "vDSO/Kernel";
        case MemoryRegionKind::MappedFile: return "Mapped File";
        case MemoryRegionKind::Anonymous:  return "Anonymous";
        case MemoryRegionKind::Unknown:    return "Unknown";
    }
    return "Unknown";
}

struct MemoryRegion {
    std::uint64_t start_address{0};
    std::uint64_t end_address{0};
    MemoryProtection protection{};
    MemoryRegionKind kind{MemoryRegionKind::Anonymous};
    std::uint64_t file_offset{0};
    std::string pathname;
    std::string module_name;

    [[nodiscard]] constexpr std::uint64_t size() const noexcept {
        return end_address >= start_address ? (end_address - start_address) : 0;
    }

    [[nodiscard]] constexpr bool contains(std::uint64_t address) const noexcept {
        return address >= start_address && address < end_address;
    }

    auto operator<=>(const MemoryRegion&) const = default;
};

struct ModuleInfo {
    std::string name;
    std::filesystem::path path;
    std::uint64_t base_address{0};
    std::uint64_t size{0};
    std::uint64_t entry_point{0};
    Format format{Format::Unknown};
    bool is_main_module{false};

    [[nodiscard]] constexpr std::uint64_t end_address() const noexcept {
        return base_address + size;
    }

    [[nodiscard]] constexpr bool contains(std::uint64_t address) const noexcept {
        return size > 0 && address >= base_address && (address - base_address) < size;
    }

    auto operator<=>(const ModuleInfo&) const = default;
};

struct MemoryWriteOptions {
    bool allow_protection_override{true};
};

struct MemorySample {
    std::vector<std::uint8_t> bytes;
    std::vector<std::uint8_t> valid;
    std::size_t readable_count{0};
};

class IProcessSession {
public:
    virtual ~IProcessSession() = default;

    [[nodiscard]] virtual const ProcessInfo& info() const noexcept = 0;
    [[nodiscard]] ProcessId pid() const noexcept { return info().pid; }
    [[nodiscard]] virtual bool is_alive() const noexcept = 0;
    [[nodiscard]] virtual Result<std::vector<MemoryRegion>> memory_regions() = 0;
    [[nodiscard]] virtual Result<std::vector<ModuleInfo>> modules() = 0;
    [[nodiscard]] virtual Result<std::size_t> read_memory(std::uint64_t address,
                                                          std::span<std::uint8_t> buffer) = 0;
    [[nodiscard]] virtual Result<std::size_t> write_memory(std::uint64_t address,
                                                           std::span<const std::uint8_t> data,
                                                           MemoryWriteOptions options = {}) = 0;
};

class IProcessBackend {
public:
    virtual ~IProcessBackend() = default;

    [[nodiscard]] virtual Result<std::vector<ProcessInfo>> list_processes() = 0;
    [[nodiscard]] virtual Result<std::unique_ptr<IProcessSession>> open_process(ProcessId pid) = 0;
};

[[nodiscard]] std::shared_ptr<IProcessBackend> create_native_process_backend();
[[nodiscard]] ProcessId current_process_id() noexcept;

[[nodiscard]] std::string strip_deleted_proc_suffix(std::string_view pathname);

/// Parse Linux `/proc/<pid>/maps` text into structured virtual memory regions.
[[nodiscard]] Result<std::vector<MemoryRegion>> parse_proc_maps(
    std::string_view maps_text,
    std::string_view main_exe_path = {});

/// Group mapped file/image regions into loaded PE/ELF modules and annotate `regions` in place
/// with `MemoryRegionKind::Image` and `module_name` where matched.
[[nodiscard]] std::vector<ModuleInfo> derive_modules_from_regions(
    std::vector<MemoryRegion>& regions,
    std::string_view main_exe_path = {},
    IProcessSession* probe_session = nullptr);

/// Read `[address, address + size)` across region/page boundaries, zero-filling unreadable or
/// unmapped holes and setting `valid[i] = 1` for every successfully read byte.
[[nodiscard]] MemorySample read_memory_tolerant(IProcessSession& session,
                                                std::span<const MemoryRegion> regions,
                                                std::uint64_t address,
                                                std::size_t size);

/// Build a live-rebased `IBinaryImage` for `module` in `session`, combining live process memory
/// with on-disk PE/ELF metadata (such as unmapped ELF `.symtab`/`.strtab` and PE directories)
/// when `module.path` is readable on disk, or parsing directly from live RAM otherwise.
[[nodiscard]] Result<std::unique_ptr<IBinaryImage>> load_live_module_image(
    IProcessSession& session,
    const ModuleInfo& module,
    std::span<const MemoryRegion> regions = {});

}  // namespace peelf
