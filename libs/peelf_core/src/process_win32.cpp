#include <cstdint>

#ifdef _WIN32

#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include "peelf/endian_reader.hpp"
#include "peelf/process.hpp"

#include <windows.h>
#include <psapi.h>
#include <tlhelp32.h>

#include <algorithm>
#include <array>
#include <cstring>
#include <format>
#include <optional>
#include <span>
#include <string>
#include <unordered_map>
#include <vector>

namespace peelf {
namespace {

class ScopedWinHandle {
public:
    ScopedWinHandle() noexcept = default;
    explicit ScopedWinHandle(HANDLE h) noexcept : handle_(h) {}

    ~ScopedWinHandle() { reset(); }

    ScopedWinHandle(const ScopedWinHandle&) = delete;
    ScopedWinHandle& operator=(const ScopedWinHandle&) = delete;

    ScopedWinHandle(ScopedWinHandle&& other) noexcept : handle_(other.release()) {}
    ScopedWinHandle& operator=(ScopedWinHandle&& other) noexcept {
        if (this != &other) {
            reset(other.release());
        }
        return *this;
    }

    [[nodiscard]] HANDLE get() const noexcept { return handle_; }
    [[nodiscard]] bool valid() const noexcept {
        return handle_ != nullptr && handle_ != INVALID_HANDLE_VALUE;
    }

    HANDLE release() noexcept {
        HANDLE h = handle_;
        handle_ = nullptr;
        return h;
    }

    void reset(HANDLE next = nullptr) noexcept {
        if (valid()) {
            ::CloseHandle(handle_);
        }
        handle_ = next;
    }

private:
    HANDLE handle_{nullptr};
};

using NtQueryInformationProcessFn = LONG(NTAPI*)(HANDLE, ULONG, PVOID, ULONG, PULONG);
using NtQueryInformationThreadFn = LONG(NTAPI*)(HANDLE, ULONG, PVOID, ULONG, PULONG);
using GetThreadDescriptionFn = HRESULT(WINAPI*)(HANDLE, PWSTR*);

struct Win32ProcessBasicInformation {
    PVOID Reserved1;
    PVOID PebBaseAddress;
    PVOID Reserved2[2];
    ULONG_PTR UniqueProcessId;
    PVOID Reserved3;
};

struct Win32ThreadBasicInformation {
    LONG ExitStatus;
    PVOID TebBaseAddress;
    struct {
        HANDLE UniqueProcess;
        HANDLE UniqueThread;
    } ClientId;
    ULONG_PTR AffinityMask;
    LONG Priority;
    LONG BasePriority;
};

[[nodiscard]] NtQueryInformationProcessFn get_nt_query_process() noexcept {
    static const NtQueryInformationProcessFn fn = []() -> NtQueryInformationProcessFn {
        HMODULE ntdll = ::GetModuleHandleW(L"ntdll.dll");
        if (ntdll == nullptr) {
            return nullptr;
        }
        return reinterpret_cast<NtQueryInformationProcessFn>(
            reinterpret_cast<void*>(::GetProcAddress(ntdll, "NtQueryInformationProcess")));
    }();
    return fn;
}

[[nodiscard]] NtQueryInformationThreadFn get_nt_query_thread() noexcept {
    static const NtQueryInformationThreadFn fn = []() -> NtQueryInformationThreadFn {
        HMODULE ntdll = ::GetModuleHandleW(L"ntdll.dll");
        if (ntdll == nullptr) {
            return nullptr;
        }
        return reinterpret_cast<NtQueryInformationThreadFn>(
            reinterpret_cast<void*>(::GetProcAddress(ntdll, "NtQueryInformationThread")));
    }();
    return fn;
}

[[nodiscard]] GetThreadDescriptionFn get_thread_description_fn() noexcept {
    static const GetThreadDescriptionFn fn = []() -> GetThreadDescriptionFn {
        HMODULE k32 = ::GetModuleHandleW(L"kernel32.dll");
        if (k32 == nullptr) {
            return nullptr;
        }
        return reinterpret_cast<GetThreadDescriptionFn>(
            reinterpret_cast<void*>(::GetProcAddress(k32, "GetThreadDescription")));
    }();
    return fn;
}

[[nodiscard]] std::string wide_to_utf8(const wchar_t* wstr) {
    if (wstr == nullptr || *wstr == L'\0') {
        return {};
    }
    const int needed = ::WideCharToMultiByte(CP_UTF8, 0, wstr, -1, nullptr, 0, nullptr, nullptr);
    if (needed <= 1) {
        return {};
    }
    std::string out(static_cast<std::size_t>(needed - 1), '\0');
    ::WideCharToMultiByte(CP_UTF8, 0, wstr, -1, out.data(), needed, nullptr, nullptr);
    return out;
}

[[nodiscard]] MemoryProtection decode_win32_protect(DWORD protect, DWORD type) noexcept {
    MemoryProtection mp{};
    mp.guarded = (protect & PAGE_GUARD) != 0;
    mp.shared = (type == MEM_MAPPED);
    const DWORD base = protect & 0xFFu;
    switch (base) {
        case PAGE_READONLY:
            mp.readable = true;
            break;
        case PAGE_READWRITE:
        case PAGE_WRITECOPY:
            mp.readable = true;
            mp.writable = true;
            break;
        case PAGE_EXECUTE:
            mp.executable = true;
            break;
        case PAGE_EXECUTE_READ:
            mp.readable = true;
            mp.executable = true;
            break;
        case PAGE_EXECUTE_READWRITE:
        case PAGE_EXECUTE_WRITECOPY:
            mp.readable = true;
            mp.writable = true;
            mp.executable = true;
            break;
        default:
            break;
    }
    return mp;
}

void detect_win32_process_arch(HANDLE process, Architecture& out_arch, bool& out_is64) noexcept {
    USHORT process_machine = IMAGE_FILE_MACHINE_UNKNOWN;
    USHORT native_machine = IMAGE_FILE_MACHINE_UNKNOWN;
    if (::IsWow64Process2(process, &process_machine, &native_machine) != 0) {
        const USHORT effective =
            (process_machine == IMAGE_FILE_MACHINE_UNKNOWN) ? native_machine : process_machine;
        switch (effective) {
            case IMAGE_FILE_MACHINE_AMD64:
                out_arch = Architecture::X86_64;
                out_is64 = true;
                return;
            case IMAGE_FILE_MACHINE_I386:
                out_arch = Architecture::X86;
                out_is64 = false;
                return;
            case IMAGE_FILE_MACHINE_ARM64:
                out_arch = Architecture::ARM64;
                out_is64 = true;
                return;
            case IMAGE_FILE_MACHINE_ARMNT:
                out_arch = Architecture::ARM;
                out_is64 = false;
                return;
            default:
                break;
        }
    }
    out_arch = sizeof(void*) == 8 ? Architecture::X86_64 : Architecture::X86;
    out_is64 = sizeof(void*) == 8;
}

[[nodiscard]] bool raw_read_process_mem(HANDLE process,
                                        std::uint64_t address,
                                        std::span<std::uint8_t> buf) noexcept {
    if (process == nullptr || buf.empty()) {
        return false;
    }
    SIZE_T got = 0;
    const BOOL ok = ::ReadProcessMemory(
        process,
        reinterpret_cast<LPCVOID>(static_cast<std::uintptr_t>(address)),
        buf.data(),
        buf.size(),
        &got);
    return ok != 0 && got == buf.size();
}

[[nodiscard]] std::string read_remote_unicode_string(HANDLE process,
                                                     std::uint64_t buffer_va,
                                                     std::uint16_t byte_len) {
    if (buffer_va == 0 || byte_len < 2u) {
        return {};
    }
    const std::size_t capped_bytes = std::min<std::size_t>(byte_len & ~std::size_t{1}, 16384u);
    std::vector<std::uint8_t> raw(capped_bytes, 0);
    if (!raw_read_process_mem(process, buffer_va, raw)) {
        return {};
    }
    const EndianReader reader(raw, Endianness::Little, AddressWidth::Bits64);
    if (auto s = reader.read_utf16_string(0, capped_bytes / 2u)) {
        return std::move(*s);
    }
    return {};
}

struct PebInspectionData {
    std::optional<std::uint64_t> peb_address;
    std::string command_line;
    std::filesystem::path working_directory;
    std::filesystem::path image_path;
    std::uint64_t environment_va{0};
    bool is_wow64_peb{false};
};

[[nodiscard]] PebInspectionData inspect_win32_peb(HANDLE process, bool target_is_64bit) {
    PebInspectionData out;
    const auto nt_query = get_nt_query_process();
    if (nt_query == nullptr || process == nullptr) {
        return out;
    }

    constexpr ULONG kProcessBasicInformation = 0u;
    constexpr ULONG kProcessWow64Information = 26u;

    ULONG_PTR wow64_peb = 0;
    ULONG ret_len = 0;
    if (!target_is_64bit && sizeof(void*) == 8 &&
        nt_query(process, kProcessWow64Information, &wow64_peb, sizeof(wow64_peb), &ret_len) >= 0 &&
        wow64_peb != 0) {
        out.peb_address = static_cast<std::uint64_t>(wow64_peb);
        out.is_wow64_peb = true;
    } else {
        Win32ProcessBasicInformation pbi{};
        if (nt_query(process, kProcessBasicInformation, &pbi, sizeof(pbi), &ret_len) >= 0 &&
            pbi.PebBaseAddress != nullptr) {
            out.peb_address = reinterpret_cast<std::uint64_t>(pbi.PebBaseAddress);
        }
    }

    if (!out.peb_address.has_value()) {
        return out;
    }

    const bool peb_64 = target_is_64bit && !out.is_wow64_peb;
    const TargetLayout layout = TargetLayout::from_arch(
        peb_64 ? Architecture::X86_64 : Architecture::X86, peb_64, Endianness::Little);

    std::array<std::uint8_t, 0x40> peb_hdr{};
    if (!raw_read_process_mem(process, *out.peb_address, peb_hdr)) {
        return out;
    }
    const EndianReader peb_reader(peb_hdr, layout);
    const std::uint64_t params_va = peb_reader.read_pointer(peb_64 ? 0x20u : 0x10u).value_or(0);
    if (params_va == 0) {
        return out;
    }

    std::array<std::uint8_t, 0x90> params_buf{};
    if (!raw_read_process_mem(process, params_va, params_buf)) {
        return out;
    }
    const EndianReader pr(params_buf, layout);
    if (peb_64) {
        const std::uint16_t cwd_len = pr.read_u16(0x38u).value_or(0);
        const std::uint64_t cwd_ptr = pr.read_u64(0x40u).value_or(0);
        const std::uint16_t img_len = pr.read_u16(0x60u).value_or(0);
        const std::uint64_t img_ptr = pr.read_u64(0x68u).value_or(0);
        const std::uint16_t cmd_len = pr.read_u16(0x70u).value_or(0);
        const std::uint64_t cmd_ptr = pr.read_u64(0x78u).value_or(0);
        out.environment_va = pr.read_u64(0x80u).value_or(0);

        if (const std::string cwd = read_remote_unicode_string(process, cwd_ptr, cwd_len);
            !cwd.empty()) {
            out.working_directory = std::filesystem::path(cwd);
        }
        if (const std::string img = read_remote_unicode_string(process, img_ptr, img_len);
            !img.empty()) {
            out.image_path = std::filesystem::path(img);
        }
        out.command_line = read_remote_unicode_string(process, cmd_ptr, cmd_len);
    } else {
        const std::uint16_t cwd_len = pr.read_u16(0x24u).value_or(0);
        const std::uint64_t cwd_ptr = pr.read_u32(0x28u).value_or(0);
        const std::uint16_t img_len = pr.read_u16(0x38u).value_or(0);
        const std::uint64_t img_ptr = pr.read_u32(0x3Cu).value_or(0);
        const std::uint16_t cmd_len = pr.read_u16(0x40u).value_or(0);
        const std::uint64_t cmd_ptr = pr.read_u32(0x44u).value_or(0);
        out.environment_va = pr.read_u32(0x48u).value_or(0);

        if (const std::string cwd = read_remote_unicode_string(process, cwd_ptr, cwd_len);
            !cwd.empty()) {
            out.working_directory = std::filesystem::path(cwd);
        }
        if (const std::string img = read_remote_unicode_string(process, img_ptr, img_len);
            !img.empty()) {
            out.image_path = std::filesystem::path(img);
        }
        out.command_line = read_remote_unicode_string(process, cmd_ptr, cmd_len);
    }

    return out;
}

[[nodiscard]] std::optional<std::uint64_t> query_win32_thread_teb(HANDLE thread,
                                                                  bool target_is_64bit) noexcept {
    const auto nt_query_thread = get_nt_query_thread();
    if (nt_query_thread == nullptr || thread == nullptr) {
        return std::nullopt;
    }
    constexpr ULONG kThreadBasicInformation = 0u;
    Win32ThreadBasicInformation tbi{};
    ULONG ret_len = 0;
    if (nt_query_thread(thread, kThreadBasicInformation, &tbi, sizeof(tbi), &ret_len) < 0 ||
        tbi.TebBaseAddress == nullptr) {
        return std::nullopt;
    }
    const auto native_teb = reinterpret_cast<std::uint64_t>(tbi.TebBaseAddress);
    if (!target_is_64bit && sizeof(void*) == 8) {
        // WOW64 32-bit TEB sits 2 pages (0x2000 bytes) after the 64-bit TEB.
        return native_teb + 0x2000ull;
    }
    return native_teb;
}

[[nodiscard]] RegisterValue make_win_reg_u64(std::string name,
                                             RegisterCategory cat,
                                             std::uint64_t val) {
    return RegisterValue{
        .name = std::move(name),
        .category = cat,
        .bit_width = 64,
        .value_u64 = val,
        .raw_bytes = encode_u64(val, Endianness::Little),
        .formatted = std::format("0x{:016x}", val),
    };
}

[[nodiscard]] RegisterValue make_win_reg_u32(std::string name,
                                             RegisterCategory cat,
                                             std::uint32_t val) {
    return RegisterValue{
        .name = std::move(name),
        .category = cat,
        .bit_width = 32,
        .value_u64 = val,
        .raw_bytes = encode_u32(val, Endianness::Little),
        .formatted = std::format("0x{:08x}", val),
    };
}

[[nodiscard]] std::vector<FlagBitInfo> decode_win_x86_flags(std::uint64_t flags) {
    return {
        {"CF", 0, ((flags >> 0u) & 1ull) != 0, "Carry Flag"},
        {"PF", 2, ((flags >> 2u) & 1ull) != 0, "Parity Flag"},
        {"AF", 4, ((flags >> 4u) & 1ull) != 0, "Auxiliary Carry Flag"},
        {"ZF", 6, ((flags >> 6u) & 1ull) != 0, "Zero Flag"},
        {"SF", 7, ((flags >> 7u) & 1ull) != 0, "Sign Flag"},
        {"TF", 8, ((flags >> 8u) & 1ull) != 0, "Trap Flag"},
        {"IF", 9, ((flags >> 9u) & 1ull) != 0, "Interrupt Enable Flag"},
        {"DF", 10, ((flags >> 10u) & 1ull) != 0, "Direction Flag"},
        {"OF", 11, ((flags >> 11u) & 1ull) != 0, "Overflow Flag"},
    };
}

class Win32ProcessSession final : public IProcessSession {
public:
    Win32ProcessSession(ProcessInfo info,
                        ScopedWinHandle handle,
                        bool has_vm_read,
                        PebInspectionData peb_data)
        : info_(std::move(info)),
          handle_(std::move(handle)),
          has_vm_read_(has_vm_read),
          peb_data_(std::move(peb_data)) {}

    ~Win32ProcessSession() override {
        if (suspended_ || !suspended_tids_.empty()) {
            (void)resume();
        }
        handle_.reset();
    }

    Win32ProcessSession(const Win32ProcessSession&) = delete;
    Win32ProcessSession& operator=(const Win32ProcessSession&) = delete;

    [[nodiscard]] const ProcessInfo& info() const noexcept override { return info_; }
    [[nodiscard]] bool is_read_only() const noexcept override { return true; }

    [[nodiscard]] bool is_alive() const noexcept override {
        if (!handle_.valid()) {
            return false;
        }
        DWORD exit_code = 0;
        return ::GetExitCodeProcess(handle_.get(), &exit_code) != 0 && exit_code == STILL_ACTIVE;
    }

    [[nodiscard]] Result<std::vector<ModuleInfo>> modules() override {
        if (!is_alive()) {
            return make_error("target process is no longer running");
        }
        ScopedWinHandle snap(
            ::CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, info_.pid));
        if (!snap.valid()) {
            return make_error("CreateToolhelp32Snapshot(TH32CS_SNAPMODULE) failed");
        }

        std::vector<ModuleInfo> result;
        MODULEENTRY32W me{};
        me.dwSize = sizeof(me);
        bool first = true;
        if (::Module32FirstW(snap.get(), &me) != 0) {
            do {
                ModuleInfo mod;
                mod.name = wide_to_utf8(me.szModule);
                mod.path = std::filesystem::path(wide_to_utf8(me.szExePath));
                mod.base_address = reinterpret_cast<std::uint64_t>(me.modBaseAddr);
                mod.size = static_cast<std::uint64_t>(me.modBaseSize);
                mod.format = Format::PE;
                mod.is_main_module = first;
                first = false;
                result.push_back(std::move(mod));
            } while (::Module32NextW(snap.get(), &me) != 0);
        }
        return result;
    }

    [[nodiscard]] Result<std::vector<MemoryRegion>> memory_regions() override {
        if (!is_alive()) {
            return make_error("target process is no longer running");
        }

        std::vector<ModuleInfo> mod_list;
        if (auto mods = modules()) {
            mod_list = std::move(*mods);
        }

        SYSTEM_INFO si{};
        ::GetNativeSystemInfo(&si);
        const std::uint64_t page_size = si.dwPageSize > 0 ? si.dwPageSize : 4096u;
        auto cursor = reinterpret_cast<std::uintptr_t>(si.lpMinimumApplicationAddress);
        const auto max_addr = reinterpret_cast<std::uintptr_t>(si.lpMaximumApplicationAddress);

        // Gather thread TEB StackLimit..StackBase ranges (non-suspending read via NT_TIB).
        struct WinStackRange {
            std::uint64_t low{0};
            std::uint64_t high{0};
            ThreadId tid{0};
        };
        std::vector<WinStackRange> thread_stacks;
        if (has_vm_read_) {
            if (auto tlist = threads()) {
                for (const ThreadInfo& ti : *tlist) {
                    ScopedWinHandle th(::OpenThread(THREAD_QUERY_LIMITED_INFORMATION,
                                                    FALSE,
                                                    static_cast<DWORD>(ti.tid)));
                    if (!th.valid()) {
                        continue;
                    }
                    const auto teb = query_win32_thread_teb(th.get(), info_.is_64bit);
                    if (!teb.has_value() || *teb == 0) {
                        continue;
                    }
                    std::array<std::uint8_t, 24> tib{};
                    const std::size_t need = info_.is_64bit ? 24u : 12u;
                    auto r = read_memory(*teb, std::span<std::uint8_t>(tib.data(), need));
                    if (!r || *r < need) {
                        continue;
                    }
                    const EndianReader rd(std::span<const std::uint8_t>(tib.data(), *r),
                                          Endianness::Little,
                                          info_.is_64bit ? AddressWidth::Bits64
                                                         : AddressWidth::Bits32);
                    const auto stack_base = rd.read_pointer(info_.is_64bit ? 0x08u : 0x04u);
                    const auto stack_limit = rd.read_pointer(info_.is_64bit ? 0x10u : 0x08u);
                    if (stack_base && stack_limit && *stack_base > *stack_limit) {
                        thread_stacks.push_back(WinStackRange{*stack_limit, *stack_base, ti.tid});
                    }
                }
            }
        }

        // Gather process heap bases from PEB ProcessHeaps (plus Toolhelp fallback).
        std::unordered_map<std::uint64_t, std::uint32_t> heap_bases;
        if (has_vm_read_ && peb_data_.peb_address.has_value() && *peb_data_.peb_address != 0) {
            const std::uint64_t peb_va = *peb_data_.peb_address;
            std::array<std::uint8_t, 16> hdr{};
            const std::uint64_t off = info_.is_64bit ? 0xE8u : 0x88u;
            const std::size_t need = info_.is_64bit ? 16u : 8u;
            if (auto r = read_memory(peb_va + off, std::span<std::uint8_t>(hdr.data(), need));
                r && *r >= need) {
                const EndianReader rd(std::span<const std::uint8_t>(hdr.data(), *r),
                                      Endianness::Little,
                                      info_.is_64bit ? AddressWidth::Bits64 : AddressWidth::Bits32);
                const std::uint32_t num_heaps = rd.read_u32(0).value_or(0);
                const std::uint64_t heaps_va = rd.read_pointer(info_.is_64bit ? 8u : 4u).value_or(0);
                const std::uint32_t capped = std::min<std::uint32_t>(num_heaps, 256u);
                const std::size_t ptr_sz = info_.is_64bit ? 8u : 4u;
                if (capped > 0 && heaps_va != 0) {
                    std::vector<std::uint8_t> ptrs(capped * ptr_sz, 0);
                    if (auto pr = read_memory(heaps_va, ptrs); pr && *pr >= ptr_sz) {
                        const EndianReader prd(std::span<const std::uint8_t>(ptrs.data(), *pr),
                                               Endianness::Little,
                                               info_.is_64bit ? AddressWidth::Bits64
                                                              : AddressWidth::Bits32);
                        for (std::uint32_t i = 0; i < capped; ++i) {
                            if (const auto hbase = prd.read_pointer(i * ptr_sz); hbase && *hbase != 0) {
                                heap_bases.emplace(*hbase, i);
                            }
                        }
                    }
                }
            }
        }
        if (heap_bases.empty()) {
            ScopedWinHandle hsnap(::CreateToolhelp32Snapshot(TH32CS_SNAPHEAPLIST,
                                                             static_cast<DWORD>(info_.pid)));
            if (hsnap.valid()) {
                HEAPLIST32 hl{};
                hl.dwSize = sizeof(hl);
                std::uint32_t idx = 0;
                if (::Heap32ListFirst(hsnap.get(), &hl)) {
                    do {
                        heap_bases.emplace(static_cast<std::uint64_t>(hl.th32HeapID), idx++);
                    } while (idx < 256u && ::Heap32ListNext(hsnap.get(), &hl));
                }
            }
        }

        // Reusable bounded batch buffer for QueryWorkingSetEx (max 4096 pages = 16 MiB exact,
        // strided sampling above 16 MiB so multi-GiB mappings never allocate giant arrays).
        constexpr std::size_t kMaxWsBatchPages = 4096u;
        std::vector<PSAPI_WORKING_SET_EX_INFORMATION> ws_batch;
        ws_batch.reserve(256u);

        std::vector<MemoryRegion> result;
        MEMORY_BASIC_INFORMATION mbi{};
        while (cursor < max_addr &&
               ::VirtualQueryEx(handle_.get(), reinterpret_cast<LPCVOID>(cursor), &mbi, sizeof(mbi)) ==
                   sizeof(mbi)) {
            const auto base = reinterpret_cast<std::uint64_t>(mbi.BaseAddress);
            const auto alloc_base = reinterpret_cast<std::uint64_t>(mbi.AllocationBase);
            const auto region_size = static_cast<std::uint64_t>(mbi.RegionSize);
            if ((mbi.State == MEM_COMMIT || mbi.State == MEM_RESERVE) && region_size > 0) {
                MemoryRegion reg;
                reg.start_address = base;
                reg.end_address = base + region_size;
                reg.usage.allocation_base = alloc_base;

                if (mbi.State == MEM_RESERVE) {
                    reg.usage.is_reserved_only = true;
                    reg.usage.committed_bytes = 0;
                    reg.protection = MemoryProtection{};
                } else {
                    reg.usage.is_reserved_only = false;
                    reg.usage.committed_bytes = region_size;
                    reg.protection = decode_win32_protect(mbi.Protect, mbi.Type);
                }

                if (mbi.Type == MEM_IMAGE) {
                    reg.kind = MemoryRegionKind::Image;
                    for (const ModuleInfo& mod : mod_list) {
                        if (mod.contains(base) || (alloc_base != 0 && mod.base_address == alloc_base)) {
                            reg.module_name = mod.name;
                            reg.pathname = mod.path.string();
                            reg.file_offset = base >= mod.base_address ? (base - mod.base_address) : 0;
                            break;
                        }
                    }
                } else if (mbi.Type == MEM_MAPPED) {
                    reg.kind = MemoryRegionKind::MappedFile;
                    std::array<wchar_t, MAX_PATH> mapped_name{};
                    if (::GetMappedFileNameW(handle_.get(),
                                             mbi.BaseAddress,
                                             mapped_name.data(),
                                             static_cast<DWORD>(mapped_name.size())) > 0) {
                        reg.pathname = wide_to_utf8(mapped_name.data());
                    }
                } else {
                    reg.kind = MemoryRegionKind::Anonymous;
                    for (const WinStackRange& sr : thread_stacks) {
                        if (reg.end_address > sr.low && reg.start_address < sr.high) {
                            reg.kind = MemoryRegionKind::Stack;
                            reg.usage.owner_tid = sr.tid;
                            break;
                        }
                    }
                    if (reg.kind == MemoryRegionKind::Anonymous) {
                        auto hit = heap_bases.find(alloc_base);
                        if (hit == heap_bases.end()) {
                            hit = heap_bases.find(base);
                        }
                        if (hit != heap_bases.end()) {
                            reg.kind = MemoryRegionKind::Heap;
                            reg.usage.heap_id = hit->second;
                        }
                    }
                }

                if (mbi.State == MEM_COMMIT) {
                    const std::uint64_t total_pages =
                        std::max<std::uint64_t>(1u, (region_size + page_size - 1u) / page_size);
                    const std::size_t sample_pages = static_cast<std::size_t>(
                        std::min<std::uint64_t>(total_pages, kMaxWsBatchPages));
                    const std::uint64_t stride =
                        total_pages > kMaxWsBatchPages ? (total_pages / kMaxWsBatchPages) : 1u;

                    ws_batch.assign(sample_pages, PSAPI_WORKING_SET_EX_INFORMATION{});
                    for (std::size_t p = 0; p < sample_pages; ++p) {
                        ws_batch[p].VirtualAddress =
                            reinterpret_cast<PVOID>(static_cast<std::uintptr_t>(
                                base + static_cast<std::uint64_t>(p) * stride * page_size));
                    }
                    if (::QueryWorkingSetEx(
                            handle_.get(),
                            ws_batch.data(),
                            static_cast<DWORD>(ws_batch.size() *
                                               sizeof(PSAPI_WORKING_SET_EX_INFORMATION))) != 0) {
                        std::uint64_t valid_pages = 0;
                        std::uint64_t shared_pages = 0;
                        std::uint64_t private_pages = 0;
                        std::uint64_t locked_pages = 0;
                        for (const auto& entry : ws_batch) {
                            if (entry.VirtualAttributes.Valid) {
                                ++valid_pages;
                                if (entry.VirtualAttributes.Shared) {
                                    ++shared_pages;
                                } else {
                                    ++private_pages;
                                }
                                if (entry.VirtualAttributes.Locked) {
                                    ++locked_pages;
                                }
                            }
                        }
                        const auto scale_bytes = [&](std::uint64_t count) -> std::uint64_t {
                            if (sample_pages == total_pages) {
                                return std::min<std::uint64_t>(count * page_size, region_size);
                            }
                            return std::min<std::uint64_t>(
                                (count * total_pages / sample_pages) * page_size, region_size);
                        };
                        reg.usage.rss_bytes = scale_bytes(valid_pages);
                        reg.usage.private_dirty_bytes = scale_bytes(private_pages);
                        reg.usage.shared_clean_bytes = scale_bytes(shared_pages);
                        reg.usage.locked_bytes = scale_bytes(locked_pages);
                    }
                } else {
                    reg.usage.rss_bytes = 0;
                }

                result.push_back(std::move(reg));
            }
            if (region_size == 0 || cursor > max_addr - static_cast<std::uintptr_t>(region_size)) {
                break;
            }
            cursor = static_cast<std::uintptr_t>(base + region_size);
        }

        return result;
    }

    [[nodiscard]] ForgivingValue<ProcessMemorySummary> memory_summary(
        std::span<const MemoryRegion> regions) override {
        std::vector<MemoryRegion> owned;
        if (regions.empty()) {
            auto fetched = memory_regions();
            if (!fetched) {
                return {std::nullopt,
                        SubsystemStatus::unavailable("VirtualQueryEx", fetched.error().message)};
            }
            owned = std::move(*fetched);
            regions = owned;
        }
        ProcessMemorySummary sum = summarize_process_memory(regions);
        PROCESS_MEMORY_COUNTERS_EX pmc{};
        pmc.cb = sizeof(pmc);
        if (::GetProcessMemoryInfo(handle_.get(),
                                   reinterpret_cast<PROCESS_MEMORY_COUNTERS*>(&pmc),
                                   sizeof(pmc)) != 0) {
            if (!sum.rss_bytes.has_value() || *sum.rss_bytes == 0) {
                sum.rss_bytes = static_cast<std::uint64_t>(pmc.WorkingSetSize);
            }
            if (!sum.private_dirty_bytes.has_value() && pmc.PrivateUsage > 0) {
                sum.private_dirty_bytes = static_cast<std::uint64_t>(pmc.PrivateUsage);
            }
        }
        const SubsystemStatus st =
            sum.rss_bytes.has_value()
                ? SubsystemStatus::available("VirtualQueryEx+QueryWorkingSetEx",
                                             "working set & VirtualQueryEx telemetry")
                : SubsystemStatus::partial("VirtualQueryEx",
                                           "working set counters unavailable; showing virtual map");
        return {std::move(sum), st};
    }

    [[nodiscard]] Result<std::size_t> read_memory(std::uint64_t address,
                                                  std::span<std::uint8_t> buffer) override {
        if (buffer.empty()) {
            return std::size_t{0};
        }
        if (!has_vm_read_) {
            return make_error("PROCESS_VM_READ was not granted for this process");
        }
        SIZE_T bytes_read = 0;
        const BOOL ok = ::ReadProcessMemory(
            handle_.get(),
            reinterpret_cast<LPCVOID>(static_cast<std::uintptr_t>(address)),
            buffer.data(),
            buffer.size(),
            &bytes_read);
        if (!ok && bytes_read == 0) {
            return make_error("ReadProcessMemory failed");
        }
        return static_cast<std::size_t>(bytes_read);
    }

    [[nodiscard]] Result<std::size_t> write_memory(std::uint64_t /*address*/,
                                                   std::span<const std::uint8_t> /*data*/,
                                                   MemoryWriteOptions /*options*/) override {
        return make_error("live process inspection is strictly read-only");
    }

    [[nodiscard]] bool is_suspended() const noexcept override { return suspended_; }

    [[nodiscard]] Result<void> suspend() override {
        if (info_.pid == current_process_id()) {
            return make_error("cannot suspend the inspector process itself");
        }
        if (!is_alive()) {
            return make_error("target process is no longer running");
        }
        if (suspended_) {
            return {};
        }

        const std::vector<ThreadId> tids = enumerate_process_tids();
        if (tids.empty()) {
            return make_error("no threads found for process");
        }

        std::size_t count = 0;
        for (const ThreadId tid : tids) {
            if (suspend_thread(tid)) {
                ++count;
            }
        }
        if (count == 0 && suspended_tids_.empty()) {
            return make_error("failed to suspend any threads in target process");
        }
        suspended_ = true;
        return {};
    }

    [[nodiscard]] Result<void> resume() override {
        const std::vector<ThreadId> copy = suspended_tids_;
        for (const ThreadId tid : copy) {
            (void)resume_thread(tid);
        }
        suspended_tids_.clear();
        suspended_ = false;
        return {};
    }

    [[nodiscard]] Result<void> suspend_thread(ThreadId tid) override {
        if (info_.pid == current_process_id()) {
            return make_error("cannot suspend the inspector process itself");
        }
        ScopedWinHandle th(::OpenThread(THREAD_SUSPEND_RESUME | THREAD_QUERY_LIMITED_INFORMATION,
                                        FALSE,
                                        static_cast<DWORD>(tid)));
        if (!th.valid()) {
            return make_error("OpenThread(THREAD_SUSPEND_RESUME) failed");
        }
        const DWORD prev =
#if defined(_M_X64) || defined(__x86_64__)
            (!info_.is_64bit) ? ::Wow64SuspendThread(th.get()) : ::SuspendThread(th.get());
#else
            ::SuspendThread(th.get());
#endif
        if (prev == static_cast<DWORD>(-1)) {
            return make_error("SuspendThread failed");
        }
        suspended_tids_.push_back(tid);
        return {};
    }

    [[nodiscard]] Result<void> resume_thread(ThreadId tid) override {
        const auto it = std::ranges::find(suspended_tids_, tid);
        if (it == suspended_tids_.end()) {
            return {};
        }
        ScopedWinHandle th(
            ::OpenThread(THREAD_SUSPEND_RESUME, FALSE, static_cast<DWORD>(tid)));
        if (!th.valid()) {
            return make_error("OpenThread(THREAD_SUSPEND_RESUME) failed");
        }
        if (::ResumeThread(th.get()) == static_cast<DWORD>(-1)) {
            return make_error("ResumeThread failed");
        }
        suspended_tids_.erase(it);
        if (suspended_tids_.empty()) {
            suspended_ = false;
        }
        return {};
    }

    [[nodiscard]] Result<std::vector<ThreadInfo>> threads() override {
        if (!is_alive()) {
            return make_error("target process is no longer running");
        }
        const std::vector<ThreadId> tids = enumerate_process_tids();
        const auto desc_fn = get_thread_description_fn();

        std::vector<ThreadInfo> out;
        out.reserve(tids.size());
        for (const ThreadId tid : tids) {
            ThreadInfo ti;
            ti.tid = tid;
            ti.is_suspended = std::ranges::find(suspended_tids_, tid) != suspended_tids_.end();
            ti.state = ti.is_suspended ? ThreadRunState::Stopped : ThreadRunState::Running;

            ScopedWinHandle th(::OpenThread(
                THREAD_QUERY_INFORMATION | THREAD_GET_CONTEXT, FALSE, static_cast<DWORD>(tid)));
            if (!th.valid()) {
                th.reset(::OpenThread(
                    THREAD_QUERY_LIMITED_INFORMATION, FALSE, static_cast<DWORD>(tid)));
            }

            if (th.valid()) {
                if (desc_fn != nullptr) {
                    PWSTR raw_desc = nullptr;
                    if (SUCCEEDED(desc_fn(th.get(), &raw_desc)) && raw_desc != nullptr) {
                        ti.name = wide_to_utf8(raw_desc);
                        ::LocalFree(raw_desc);
                    }
                }
                if (const auto teb = query_win32_thread_teb(th.get(), info_.is_64bit)) {
                    ti.teb_address = *teb;
                    ti.tls_base = *teb;
                }
                if (const auto nt_query_thread = get_nt_query_thread()) {
                    constexpr ULONG kThreadQuerySetWin32StartAddress = 9u;
                    ULONG_PTR start_va = 0;
                    ULONG ret_len = 0;
                    if (nt_query_thread(th.get(),
                                        kThreadQuerySetWin32StartAddress,
                                        &start_va,
                                        sizeof(start_va),
                                        &ret_len) >= 0 &&
                        start_va != 0) {
                        ti.start_address = static_cast<std::uint64_t>(start_va);
                    }
                }
                FILETIME ft_create{};
                FILETIME ft_exit{};
                FILETIME ft_kernel{};
                FILETIME ft_user{};
                if (::GetThreadTimes(th.get(), &ft_create, &ft_exit, &ft_kernel, &ft_user) != FALSE) {
                    const std::uint64_t k100 =
                        (static_cast<std::uint64_t>(ft_kernel.dwHighDateTime) << 32u) |
                        static_cast<std::uint64_t>(ft_kernel.dwLowDateTime);
                    const std::uint64_t u100 =
                        (static_cast<std::uint64_t>(ft_user.dwHighDateTime) << 32u) |
                        static_cast<std::uint64_t>(ft_user.dwLowDateTime);
                    ti.kernel_time_ns = k100 * 100ULL;
                    ti.user_time_ns = u100 * 100ULL;
                }
                ti.status = SubsystemStatus::available("Win32 Thread", "thread handle accessible");
            } else {
                ti.status = SubsystemStatus::partial(
                    "Toolhelp32", "thread listed in snapshot; OpenThread restricted");
            }
            out.push_back(std::move(ti));
        }

        return out;
    }

    [[nodiscard]] ThreadContext thread_context(ThreadId tid) override {
        ThreadContext ctx;
        ctx.tid = tid;
        ctx.layout = target_layout();

        ScopedWinHandle th(::OpenThread(
            THREAD_GET_CONTEXT | THREAD_SUSPEND_RESUME | THREAD_QUERY_INFORMATION,
            FALSE,
            static_cast<DWORD>(tid)));
        bool can_suspend = th.valid();
        if (!th.valid()) {
            can_suspend = false;
            th.reset(::OpenThread(THREAD_GET_CONTEXT | THREAD_QUERY_LIMITED_INFORMATION,
                                  FALSE,
                                  static_cast<DWORD>(tid)));
        }
        if (!th.valid()) {
            ctx.status = SubsystemStatus::unavailable(
                "OpenThread", "permission denied opening thread for THREAD_GET_CONTEXT");
            return ctx;
        }

        ctx.teb_address = query_win32_thread_teb(th.get(), info_.is_64bit);
        ctx.tls_pointer = ctx.teb_address;

        const bool is_self =
            (info_.pid == current_process_id() && tid == static_cast<ThreadId>(::GetCurrentThreadId()));
        const bool already_paused =
            std::ranges::find(suspended_tids_, tid) != suspended_tids_.end();

        bool transiently_paused = false;
        if (can_suspend && !is_self && !already_paused) {
            const DWORD prev =
#if defined(_M_X64) || defined(__x86_64__)
                (!info_.is_64bit) ? ::Wow64SuspendThread(th.get()) : ::SuspendThread(th.get());
#else
                ::SuspendThread(th.get());
#endif
            if (prev != static_cast<DWORD>(-1)) {
                transiently_paused = true;
            }
        }
        struct ScopedThreadResume {
            HANDLE h;
            bool active;
            ~ScopedThreadResume() {
                if (active && h != nullptr) {
                    (void)::ResumeThread(h);
                }
            }
        } resume_guard{th.get(), transiently_paused};

#if defined(_M_X64) || defined(__x86_64__)
        if (!info_.is_64bit) {
            WOW64_CONTEXT wctx{};
            wctx.ContextFlags = WOW64_CONTEXT_FULL | WOW64_CONTEXT_SEGMENTS;
            if (::Wow64GetThreadContext(th.get(), &wctx) == 0) {
                ctx.status =
                    SubsystemStatus::unavailable("Wow64GetThreadContext", "failed to read WOW64 context");
                return ctx;
            }
            ctx.registers.push_back(make_win_reg_u32("eax", RegisterCategory::General, wctx.Eax));
            ctx.registers.push_back(make_win_reg_u32("ebx", RegisterCategory::General, wctx.Ebx));
            ctx.registers.push_back(make_win_reg_u32("ecx", RegisterCategory::General, wctx.Ecx));
            ctx.registers.push_back(make_win_reg_u32("edx", RegisterCategory::General, wctx.Edx));
            ctx.registers.push_back(make_win_reg_u32("esi", RegisterCategory::General, wctx.Esi));
            ctx.registers.push_back(make_win_reg_u32("edi", RegisterCategory::General, wctx.Edi));
            ctx.registers.push_back(make_win_reg_u32("ebp", RegisterCategory::FramePointer, wctx.Ebp));
            ctx.registers.push_back(make_win_reg_u32("esp", RegisterCategory::StackPointer, wctx.Esp));
            ctx.registers.push_back(
                make_win_reg_u32("eip", RegisterCategory::InstructionPointer, wctx.Eip));
            ctx.registers.push_back(make_win_reg_u32("eflags", RegisterCategory::Flags, wctx.EFlags));

            ctx.instruction_pointer = wctx.Eip;
            ctx.stack_pointer = wctx.Esp;
            ctx.frame_pointer = wctx.Ebp;
            ctx.flags_value = wctx.EFlags;
            ctx.decoded_flags = decode_win_x86_flags(wctx.EFlags);
            ctx.status = SubsystemStatus::available("Wow64GetThreadContext", "WOW64 x86 register context");
            return ctx;
        }

        alignas(16) CONTEXT nctx{};
        nctx.ContextFlags = CONTEXT_FULL | CONTEXT_SEGMENTS;
        if (::GetThreadContext(th.get(), &nctx) == 0) {
            ctx.status = SubsystemStatus::unavailable("GetThreadContext", "failed to read x64 context");
            return ctx;
        }
        ctx.registers.push_back(make_win_reg_u64("rax", RegisterCategory::General, nctx.Rax));
        ctx.registers.push_back(make_win_reg_u64("rbx", RegisterCategory::General, nctx.Rbx));
        ctx.registers.push_back(make_win_reg_u64("rcx", RegisterCategory::General, nctx.Rcx));
        ctx.registers.push_back(make_win_reg_u64("rdx", RegisterCategory::General, nctx.Rdx));
        ctx.registers.push_back(make_win_reg_u64("rsi", RegisterCategory::General, nctx.Rsi));
        ctx.registers.push_back(make_win_reg_u64("rdi", RegisterCategory::General, nctx.Rdi));
        ctx.registers.push_back(make_win_reg_u64("rbp", RegisterCategory::FramePointer, nctx.Rbp));
        ctx.registers.push_back(make_win_reg_u64("rsp", RegisterCategory::StackPointer, nctx.Rsp));
        ctx.registers.push_back(make_win_reg_u64("r8", RegisterCategory::General, nctx.R8));
        ctx.registers.push_back(make_win_reg_u64("r9", RegisterCategory::General, nctx.R9));
        ctx.registers.push_back(make_win_reg_u64("r10", RegisterCategory::General, nctx.R10));
        ctx.registers.push_back(make_win_reg_u64("r11", RegisterCategory::General, nctx.R11));
        ctx.registers.push_back(make_win_reg_u64("r12", RegisterCategory::General, nctx.R12));
        ctx.registers.push_back(make_win_reg_u64("r13", RegisterCategory::General, nctx.R13));
        ctx.registers.push_back(make_win_reg_u64("r14", RegisterCategory::General, nctx.R14));
        ctx.registers.push_back(make_win_reg_u64("r15", RegisterCategory::General, nctx.R15));
        ctx.registers.push_back(
            make_win_reg_u64("rip", RegisterCategory::InstructionPointer, nctx.Rip));
        ctx.registers.push_back(make_win_reg_u64("rflags", RegisterCategory::Flags, nctx.EFlags));
        if (ctx.teb_address.has_value()) {
            ctx.registers.push_back(
                make_win_reg_u64("gs_base", RegisterCategory::SegmentOrTls, *ctx.teb_address));
        }

        ctx.instruction_pointer = nctx.Rip;
        ctx.stack_pointer = nctx.Rsp;
        ctx.frame_pointer = nctx.Rbp;
        ctx.flags_value = nctx.EFlags;
        ctx.decoded_flags = decode_win_x86_flags(nctx.EFlags);
        ctx.status = SubsystemStatus::available("GetThreadContext", "x64 register context");
        return ctx;
#elif defined(_M_ARM64) || defined(__aarch64__)
        alignas(16) CONTEXT nctx{};
        nctx.ContextFlags = CONTEXT_FULL;
        if (::GetThreadContext(th.get(), &nctx) == 0) {
            ctx.status = SubsystemStatus::unavailable("GetThreadContext", "failed to read ARM64 context");
            return ctx;
        }
        for (std::size_t i = 0; i < 29u; ++i) {
            ctx.registers.push_back(
                make_win_reg_u64(std::format("x{}", i), RegisterCategory::General, nctx.X[i]));
        }
        ctx.registers.push_back(make_win_reg_u64("fp", RegisterCategory::FramePointer, nctx.Fp));
        ctx.registers.push_back(make_win_reg_u64("lr", RegisterCategory::General, nctx.Lr));
        ctx.registers.push_back(make_win_reg_u64("sp", RegisterCategory::StackPointer, nctx.Sp));
        ctx.registers.push_back(
            make_win_reg_u64("pc", RegisterCategory::InstructionPointer, nctx.Pc));
        ctx.registers.push_back(make_win_reg_u64("cpsr", RegisterCategory::Flags, nctx.Cpsr));

        ctx.frame_pointer = nctx.Fp;
        ctx.link_register = nctx.Lr;
        ctx.stack_pointer = nctx.Sp;
        ctx.instruction_pointer = nctx.Pc;
        ctx.flags_value = nctx.Cpsr;
        if (nctx.X[18] != 0) {
            ctx.teb_address = nctx.X[18];
            ctx.tls_pointer = nctx.X[18];
        }
        ctx.status = SubsystemStatus::available("GetThreadContext", "ARM64 register context");
        return ctx;
#elif defined(_M_IX86) || defined(__i386__)
        CONTEXT nctx{};
        nctx.ContextFlags = CONTEXT_FULL | CONTEXT_SEGMENTS;
        if (::GetThreadContext(th.get(), &nctx) == 0) {
            ctx.status = SubsystemStatus::unavailable("GetThreadContext", "failed to read x86 context");
            return ctx;
        }
        ctx.registers.push_back(make_win_reg_u32("eax", RegisterCategory::General, nctx.Eax));
        ctx.registers.push_back(make_win_reg_u32("ebx", RegisterCategory::General, nctx.Ebx));
        ctx.registers.push_back(make_win_reg_u32("ecx", RegisterCategory::General, nctx.Ecx));
        ctx.registers.push_back(make_win_reg_u32("edx", RegisterCategory::General, nctx.Edx));
        ctx.registers.push_back(make_win_reg_u32("esi", RegisterCategory::General, nctx.Esi));
        ctx.registers.push_back(make_win_reg_u32("edi", RegisterCategory::General, nctx.Edi));
        ctx.registers.push_back(make_win_reg_u32("ebp", RegisterCategory::FramePointer, nctx.Ebp));
        ctx.registers.push_back(make_win_reg_u32("esp", RegisterCategory::StackPointer, nctx.Esp));
        ctx.registers.push_back(
            make_win_reg_u32("eip", RegisterCategory::InstructionPointer, nctx.Eip));
        ctx.registers.push_back(make_win_reg_u32("eflags", RegisterCategory::Flags, nctx.EFlags));
        ctx.instruction_pointer = nctx.Eip;
        ctx.stack_pointer = nctx.Esp;
        ctx.frame_pointer = nctx.Ebp;
        ctx.flags_value = nctx.EFlags;
        ctx.decoded_flags = decode_win_x86_flags(nctx.EFlags);
        ctx.status = SubsystemStatus::available("GetThreadContext", "x86 register context");
        return ctx;
#else
        ctx.status = SubsystemStatus::unavailable("GetThreadContext", "unsupported Win32 host architecture");
        return ctx;
#endif
    }

    [[nodiscard]] ForgivingValue<std::uint64_t> process_environment_block_address() override {
        if (peb_data_.peb_address.has_value()) {
            return {*peb_data_.peb_address,
                    SubsystemStatus::available("NtQueryInformationProcess", "PEB base address")};
        }
        return {std::nullopt,
                SubsystemStatus::unavailable("NtQueryInformationProcess", "PEB address unavailable")};
    }

    [[nodiscard]] ForgivingValue<std::vector<std::string>> environment_variables() override {
        if (!has_vm_read_ || peb_data_.environment_va == 0) {
            return {std::nullopt,
                    SubsystemStatus::unavailable(
                        "RTL_USER_PROCESS_PARAMETERS", "environment block address unavailable")};
        }

        std::vector<std::uint8_t> env_bytes(65536u, 0);
        auto read_res = read_memory(peb_data_.environment_va, env_bytes);
        if (!read_res || *read_res < 4u) {
            return {std::nullopt,
                    SubsystemStatus::unavailable("ReadProcessMemory",
                                                 "failed to read UTF-16 environment block")};
        }
        env_bytes.resize(*read_res);

        const EndianReader reader(env_bytes, Endianness::Little, AddressWidth::Bits64);
        std::vector<std::string> vars;
        std::size_t off = 0;
        constexpr std::size_t kMaxVars = 512u;
        while (off + 2u <= env_bytes.size() && vars.size() < kMaxVars) {
            const auto first_cu = reader.read_u16(off);
            if (!first_cu || *first_cu == 0) {
                break;
            }
            auto entry = reader.read_utf16_string(off, (env_bytes.size() - off) / 2u);
            if (!entry || entry->empty()) {
                break;
            }
            // Advance past NUL-terminated UTF-16 entry.
            while (off + 2u <= env_bytes.size()) {
                const auto cu = reader.read_u16(off);
                off += 2u;
                if (!cu || *cu == 0) {
                    break;
                }
            }
            vars.push_back(std::move(*entry));
        }

        return {std::move(vars),
                SubsystemStatus::available("RTL_USER_PROCESS_PARAMETERS", "UTF-16 environment")};
    }

private:
    [[nodiscard]] std::vector<ThreadId> enumerate_process_tids() const {
        ScopedWinHandle snap(::CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0));
        if (!snap.valid()) {
            return {};
        }
        std::vector<ThreadId> tids;
        THREADENTRY32 te{};
        te.dwSize = sizeof(te);
        if (::Thread32First(snap.get(), &te) != 0) {
            do {
                if (te.th32OwnerProcessID == static_cast<DWORD>(info_.pid)) {
                    tids.push_back(static_cast<ThreadId>(te.th32ThreadID));
                }
            } while (::Thread32Next(snap.get(), &te) != 0);
        }
        std::ranges::sort(tids);
        return tids;
    }

    ProcessInfo info_;
    ScopedWinHandle handle_;
    bool has_vm_read_{false};
    PebInspectionData peb_data_{};
    std::vector<ThreadId> suspended_tids_;
    bool suspended_{false};
};

class Win32ProcessBackend final : public IProcessBackend {
public:
    Result<std::vector<ProcessInfo>> list_processes() override {
        ScopedWinHandle snap(::CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0));
        if (!snap.valid()) {
            return make_error("CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS) failed");
        }

        std::vector<ProcessInfo> list;
        PROCESSENTRY32W pe{};
        pe.dwSize = sizeof(pe);
        if (::Process32FirstW(snap.get(), &pe) != 0) {
            do {
                if (pe.th32ProcessID == 0) {
                    continue;
                }
                ProcessInfo info;
                info.pid = static_cast<ProcessId>(pe.th32ProcessID);
                info.parent_pid = static_cast<ProcessId>(pe.th32ParentProcessID);
                info.name = wide_to_utf8(pe.szExeFile);
                info.endianness = Endianness::Little;

                // Strictly read-only OpenProcess: never request PROCESS_VM_WRITE / PROCESS_VM_OPERATION.
                bool has_vm_read = true;
                ScopedWinHandle h(::OpenProcess(
                    PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, FALSE, pe.th32ProcessID));
                if (!h.valid()) {
                    has_vm_read = false;
                    h.reset(
                        ::OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pe.th32ProcessID));
                }

                if (h.valid()) {
                    info.access = ProcessAccessStatus::ReadOnly;
                    std::array<wchar_t, MAX_PATH> path_buf{};
                    DWORD path_len = static_cast<DWORD>(path_buf.size());
                    if (::QueryFullProcessImageNameW(h.get(), 0, path_buf.data(), &path_len) != 0) {
                        info.executable_path =
                            std::filesystem::path(wide_to_utf8(path_buf.data()));
                    }
                    detect_win32_process_arch(h.get(), info.architecture, info.is_64bit);
                    if (has_vm_read) {
                        const PebInspectionData peb = inspect_win32_peb(h.get(), info.is_64bit);
                        info.command_line = peb.command_line;
                        info.working_directory = peb.working_directory;
                        if (info.executable_path.empty() && !peb.image_path.empty()) {
                            info.executable_path = peb.image_path;
                        }
                        if (info.executable_path.empty() && !info.command_line.empty()) {
                            if (const auto resolved = resolve_executable_from_command_line(
                                    info.command_line, info.working_directory, {}, true)) {
                                info.executable_path = *resolved;
                            }
                        }
                    }
                } else {
                    info.access = ProcessAccessStatus::AccessDenied;
                }
                list.push_back(std::move(info));
            } while (::Process32NextW(snap.get(), &pe) != 0);
        }

        std::ranges::sort(list, [](const ProcessInfo& a, const ProcessInfo& b) {
            return a.pid < b.pid;
        });
        return list;
    }

    Result<std::unique_ptr<IProcessSession>> open_process(ProcessId pid) override {
        if (pid == 0) {
            return make_error("invalid PID 0");
        }

        // Strictly read-only attach tiers (never request PROCESS_VM_WRITE or PROCESS_VM_OPERATION).
        bool has_vm_read = true;
        ScopedWinHandle h(::OpenProcess(
            PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | SYNCHRONIZE,
            FALSE,
            static_cast<DWORD>(pid)));
        if (!h.valid()) {
            h.reset(::OpenProcess(
                PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ,
                FALSE,
                static_cast<DWORD>(pid)));
        }
        if (!h.valid()) {
            has_vm_read = false;
            h.reset(::OpenProcess(
                PROCESS_QUERY_LIMITED_INFORMATION, FALSE, static_cast<DWORD>(pid)));
        }
        if (!h.valid()) {
            return make_error("OpenProcess failed (access denied or process exited)");
        }

        ProcessInfo info;
        info.pid = pid;
        info.endianness = Endianness::Little;
        info.access = ProcessAccessStatus::ReadOnly;

        std::array<wchar_t, MAX_PATH> path_buf{};
        DWORD path_len = static_cast<DWORD>(path_buf.size());
        if (::QueryFullProcessImageNameW(h.get(), 0, path_buf.data(), &path_len) != 0) {
            info.executable_path = std::filesystem::path(wide_to_utf8(path_buf.data()));
            info.name = info.executable_path.filename().string();
        }
        detect_win32_process_arch(h.get(), info.architecture, info.is_64bit);

        PebInspectionData peb =
            has_vm_read ? inspect_win32_peb(h.get(), info.is_64bit) : PebInspectionData{};
        info.command_line = peb.command_line;
        info.working_directory = peb.working_directory;
        if (info.executable_path.empty() && !peb.image_path.empty()) {
            info.executable_path = peb.image_path;
        }
        if (info.executable_path.empty() && !info.command_line.empty()) {
            if (const auto resolved = resolve_executable_from_command_line(
                    info.command_line, info.working_directory, {}, true)) {
                info.executable_path = *resolved;
            }
        }
        if (info.name.empty() && !info.executable_path.empty()) {
            info.name = info.executable_path.filename().string();
        }

        return std::make_unique<Win32ProcessSession>(
            std::move(info), std::move(h), has_vm_read, std::move(peb));
    }
};

}  // namespace

std::shared_ptr<IProcessBackend> create_native_process_backend() {
    return std::make_shared<Win32ProcessBackend>();
}

}  // namespace peelf

#endif  // _WIN32
