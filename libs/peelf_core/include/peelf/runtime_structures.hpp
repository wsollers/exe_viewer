#pragma once

#include <peelf/binary_image.hpp>
#include <peelf/endian_reader.hpp>
#include <peelf/forgiving.hpp>
#include <peelf/process.hpp>

#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <vector>

namespace peelf {

struct DecodedField {
    std::string name;
    std::optional<std::uint64_t> offset;
    std::optional<std::uint64_t> raw_value;
    std::string formatted_value;
    std::string description;
};

struct RuntimeModuleEntry {
    std::string name;
    std::string full_path;
    std::uint64_t base_address{0};
    std::uint64_t size_or_dynamic_va{0};
    std::uint64_t entry_point{0};
};

struct AuxvEntry {
    std::uint64_t type{0};
    std::string type_name;
    std::uint64_t value{0};
    std::string formatted_value;
    std::string description;
};

/// Unified Process Environment Block snapshot:
/// - Windows PE: PEB32 / PEB64, RTL_USER_PROCESS_PARAMETERS, PEB_LDR_DATA InLoadOrderModuleList.
/// - Linux ELF: /proc/<pid>/auxv, /proc/<pid>/status (TracerPid, Seccomp, NoNewPrivs, CapEff),
///   cmdline/cwd/environ, and DT_DEBUG -> r_debug / link_map dynamic loader chain.
struct ProcessEnvironmentSnapshot {
    Format os_family{Format::Unknown};
    TargetLayout layout{};
    std::optional<std::uint64_t> block_address;
    bool debugger_present{false};
    std::string debugger_detail;
    std::string image_path;
    std::string command_line;
    std::string current_directory;
    std::vector<std::string> environment_sample;
    std::vector<DecodedField> core_fields;
    std::vector<DecodedField> process_parameters;
    std::vector<RuntimeModuleEntry> loader_modules;
    std::vector<AuxvEntry> auxv_entries;
    std::vector<DecodedField> security_and_status_fields;

    SubsystemStatus core_status{};
    SubsystemStatus parameters_status{};
    SubsystemStatus loader_status{};
    SubsystemStatus auxv_status{};
    SubsystemStatus status_fields_status{};
};

/// Unified Thread Environment Block snapshot:
/// - Windows PE: TEB32 / TEB64 (NT_TIB ExceptionList, StackBase, StackLimit, Self, ClientId,
///   ThreadLocalStoragePointer, LastErrorValue).
/// - Linux ELF: /proc/<pid>/task/<tid> runtime fields, mapped thread stack bounds, architecture
///   thread pointer (fs_base / gs_base / tpidr_el0 / tp), and glibc/musl TCB header (tcbhead_t:
///   self, dtv, stack_guard canary, pointer_guard) when readable.
struct ThreadEnvironmentSnapshot {
    ThreadId tid{0};
    Format os_family{Format::Unknown};
    TargetLayout layout{};
    std::optional<std::uint64_t> block_address;
    std::optional<std::uint64_t> stack_base;
    std::optional<std::uint64_t> stack_limit;
    std::optional<std::uint64_t> tls_array_or_dtv;
    std::optional<std::uint64_t> exception_list;
    std::optional<std::uint64_t> stack_guard_canary;
    std::optional<std::uint64_t> pointer_guard;
    std::uint32_t last_error_or_errno{0};
    std::vector<DecodedField> fields;
    SubsystemStatus status{};
};

struct HarvestedFlagItem {
    std::string category;
    std::string name;
    std::uint64_t mask{0};
    bool active{false};
    std::string value_text;
    std::string description;
};

struct HeaderFlagsReport {
    Format format{Format::Unknown};
    TargetLayout layout{};
    std::vector<DecodedField> raw_masks;
    std::vector<HarvestedFlagItem> flags;
    std::vector<DecodedField> security_summary;
    SubsystemStatus status{};
};

[[nodiscard]] HeaderFlagsReport harvest_header_flags(const IBinaryImage& image);

[[nodiscard]] ProcessEnvironmentSnapshot inspect_process_environment(
    IProcessSession& session,
    std::span<const MemoryRegion> regions,
    std::span<const ModuleInfo> modules,
    const IBinaryImage* main_image = nullptr);

[[nodiscard]] ThreadEnvironmentSnapshot inspect_thread_environment(
    IProcessSession& session,
    const ThreadInfo& thread_info,
    const ThreadContext* thread_ctx,
    std::span<const MemoryRegion> regions);

}  // namespace peelf
