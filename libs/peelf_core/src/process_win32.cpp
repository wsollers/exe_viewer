#include <cstdint>

#ifdef _WIN32

#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include "peelf/process.hpp"

#include <windows.h>
#include <psapi.h>
#include <tlhelp32.h>

#include <algorithm>
#include <array>
#include <string>
#include <unordered_map>
#include <vector>

namespace peelf {
namespace {

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

class Win32ProcessSession final : public IProcessSession {
public:
    Win32ProcessSession(ProcessInfo info, HANDLE handle, bool can_write)
        : info_(std::move(info)), handle_(handle), can_write_(can_write) {}

    ~Win32ProcessSession() override {
        if (handle_ != nullptr && handle_ != INVALID_HANDLE_VALUE) {
            ::CloseHandle(handle_);
            handle_ = nullptr;
        }
    }

    Win32ProcessSession(const Win32ProcessSession&) = delete;
    Win32ProcessSession& operator=(const Win32ProcessSession&) = delete;

    [[nodiscard]] const ProcessInfo& info() const noexcept override { return info_; }

    [[nodiscard]] bool is_alive() const noexcept override {
        if (handle_ == nullptr) {
            return false;
        }
        DWORD exit_code = 0;
        return ::GetExitCodeProcess(handle_, &exit_code) != 0 && exit_code == STILL_ACTIVE;
    }

    [[nodiscard]] Result<std::vector<ModuleInfo>> modules() override {
        if (!is_alive()) {
            return make_error("target process is no longer running");
        }
        HANDLE snap =
            ::CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, info_.pid);
        if (snap == INVALID_HANDLE_VALUE) {
            return make_error("CreateToolhelp32Snapshot(TH32CS_SNAPMODULE) failed");
        }

        std::vector<ModuleInfo> result;
        MODULEENTRY32W me{};
        me.dwSize = sizeof(me);
        bool first = true;
        if (::Module32FirstW(snap, &me) != 0) {
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
            } while (::Module32NextW(snap, &me) != 0);
        }
        ::CloseHandle(snap);
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
        auto cursor = reinterpret_cast<std::uintptr_t>(si.lpMinimumApplicationAddress);
        const auto max_addr = reinterpret_cast<std::uintptr_t>(si.lpMaximumApplicationAddress);

        std::vector<MemoryRegion> result;
        MEMORY_BASIC_INFORMATION mbi{};
        while (cursor < max_addr &&
               ::VirtualQueryEx(handle_, reinterpret_cast<LPCVOID>(cursor), &mbi, sizeof(mbi)) ==
                   sizeof(mbi)) {
            const auto base = reinterpret_cast<std::uint64_t>(mbi.BaseAddress);
            const auto region_size = static_cast<std::uint64_t>(mbi.RegionSize);
            if (mbi.State == MEM_COMMIT && region_size > 0) {
                MemoryRegion reg;
                reg.start_address = base;
                reg.end_address = base + region_size;
                reg.protection = decode_win32_protect(mbi.Protect, mbi.Type);
                if (mbi.Type == MEM_IMAGE) {
                    reg.kind = MemoryRegionKind::Image;
                    for (const ModuleInfo& mod : mod_list) {
                        if (mod.contains(base)) {
                            reg.module_name = mod.name;
                            reg.pathname = mod.path.string();
                            reg.file_offset = base - mod.base_address;
                            break;
                        }
                    }
                } else if (mbi.Type == MEM_MAPPED) {
                    reg.kind = MemoryRegionKind::MappedFile;
                    std::array<wchar_t, MAX_PATH> mapped_name{};
                    if (::GetMappedFileNameW(handle_,
                                             mbi.BaseAddress,
                                             mapped_name.data(),
                                             static_cast<DWORD>(mapped_name.size())) > 0) {
                        reg.pathname = wide_to_utf8(mapped_name.data());
                    }
                } else {
                    reg.kind = MemoryRegionKind::Anonymous;
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

    [[nodiscard]] Result<std::size_t> read_memory(std::uint64_t address,
                                                  std::span<std::uint8_t> buffer) override {
        if (buffer.empty()) {
            return std::size_t{0};
        }
        SIZE_T bytes_read = 0;
        const BOOL ok = ::ReadProcessMemory(
            handle_,
            reinterpret_cast<LPCVOID>(static_cast<std::uintptr_t>(address)),
            buffer.data(),
            buffer.size(),
            &bytes_read);
        if (!ok && bytes_read == 0) {
            return make_error("ReadProcessMemory failed");
        }
        return static_cast<std::size_t>(bytes_read);
    }

    [[nodiscard]] Result<std::size_t> write_memory(std::uint64_t address,
                                                   std::span<const std::uint8_t> data,
                                                   MemoryWriteOptions options) override {
        if (data.empty()) {
            return std::size_t{0};
        }
        if (!can_write_) {
            return make_error("process session was opened read-only");
        }

        auto* remote = reinterpret_cast<LPVOID>(static_cast<std::uintptr_t>(address));
        SIZE_T written = 0;
        if (::WriteProcessMemory(handle_, remote, data.data(), data.size(), &written) != 0) {
            ::FlushInstructionCache(handle_, remote, written);
            return static_cast<std::size_t>(written);
        }

        if (!options.allow_protection_override) {
            return make_error("WriteProcessMemory failed and protection override is disabled");
        }

        DWORD old_protect = 0;
        if (::VirtualProtectEx(
                handle_, remote, data.size(), PAGE_EXECUTE_READWRITE, &old_protect) == 0) {
            return make_error("VirtualProtectEx failed to temporarily make page writable");
        }

        const BOOL ok = ::WriteProcessMemory(handle_, remote, data.data(), data.size(), &written);
        if (ok != 0) {
            ::FlushInstructionCache(handle_, remote, written);
        }
        DWORD dummy = 0;
        (void)::VirtualProtectEx(handle_, remote, data.size(), old_protect, &dummy);

        if (ok == 0 && written == 0) {
            return make_error("WriteProcessMemory failed after VirtualProtectEx");
        }
        return static_cast<std::size_t>(written);
    }

private:
    ProcessInfo info_;
    HANDLE handle_{nullptr};
    bool can_write_{false};
};

class Win32ProcessBackend final : public IProcessBackend {
public:
    Result<std::vector<ProcessInfo>> list_processes() override {
        HANDLE snap = ::CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snap == INVALID_HANDLE_VALUE) {
            return make_error("CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS) failed");
        }

        std::vector<ProcessInfo> list;
        PROCESSENTRY32W pe{};
        pe.dwSize = sizeof(pe);
        if (::Process32FirstW(snap, &pe) != 0) {
            do {
                if (pe.th32ProcessID == 0) {
                    continue;
                }
                ProcessInfo info;
                info.pid = static_cast<ProcessId>(pe.th32ProcessID);
                info.parent_pid = static_cast<ProcessId>(pe.th32ParentProcessID);
                info.name = wide_to_utf8(pe.szExeFile);

                HANDLE h = ::OpenProcess(
                    PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, FALSE, pe.th32ProcessID);
                if (h != nullptr) {
                    std::array<wchar_t, MAX_PATH> path_buf{};
                    DWORD path_len = static_cast<DWORD>(path_buf.size());
                    if (::QueryFullProcessImageNameW(h, 0, path_buf.data(), &path_len) != 0) {
                        info.executable_path =
                            std::filesystem::path(wide_to_utf8(path_buf.data()));
                    }
                    detect_win32_process_arch(h, info.architecture, info.is_64bit);
                    HANDLE rw = ::OpenProcess(
                        PROCESS_VM_WRITE | PROCESS_VM_OPERATION, FALSE, pe.th32ProcessID);
                    if (rw != nullptr) {
                        info.access = ProcessAccessStatus::Accessible;
                        ::CloseHandle(rw);
                    } else {
                        info.access = ProcessAccessStatus::ReadOnly;
                    }
                    ::CloseHandle(h);
                } else {
                    info.access = ProcessAccessStatus::AccessDenied;
                }
                list.push_back(std::move(info));
            } while (::Process32NextW(snap, &pe) != 0);
        }

        ::CloseHandle(snap);
        std::ranges::sort(list, [](const ProcessInfo& a, const ProcessInfo& b) {
            return a.pid < b.pid;
        });
        return list;
    }

    Result<std::unique_ptr<IProcessSession>> open_process(ProcessId pid) override {
        if (pid == 0) {
            return make_error("invalid PID 0");
        }
        bool can_write = true;
        HANDLE h = ::OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_VM_WRITE |
                                     PROCESS_VM_OPERATION,
                                 FALSE,
                                 static_cast<DWORD>(pid));
        if (h == nullptr) {
            can_write = false;
            h = ::OpenProcess(
                PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, FALSE, static_cast<DWORD>(pid));
        }
        if (h == nullptr) {
            return make_error("OpenProcess failed (access denied or process exited)");
        }

        ProcessInfo info;
        info.pid = pid;
        info.access = can_write ? ProcessAccessStatus::Accessible : ProcessAccessStatus::ReadOnly;
        std::array<wchar_t, MAX_PATH> path_buf{};
        DWORD path_len = static_cast<DWORD>(path_buf.size());
        if (::QueryFullProcessImageNameW(h, 0, path_buf.data(), &path_len) != 0) {
            info.executable_path = std::filesystem::path(wide_to_utf8(path_buf.data()));
            info.name = info.executable_path.filename().string();
        }
        detect_win32_process_arch(h, info.architecture, info.is_64bit);
        return std::make_unique<Win32ProcessSession>(std::move(info), h, can_write);
    }
};

}  // namespace

std::shared_ptr<IProcessBackend> create_native_process_backend() {
    return std::make_shared<Win32ProcessBackend>();
}

}  // namespace peelf

#endif  // _WIN32
