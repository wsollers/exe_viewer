#include "crash/crash_handler.hpp"

#include <array>
#include <csignal>
#include <cstdarg>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <exception>
#include <string>
#include <string_view>

#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <crtdbg.h>
#include <windows.h>
#include <dbghelp.h>
#else
#include <execinfo.h>
#include <fcntl.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#endif

namespace viewer::crash {
namespace {

void write_file_text(const char* path, std::string_view text) noexcept {
    std::fwrite(text.data(), 1, text.size(), stderr);
    std::fflush(stderr);

#ifdef _WIN32
    std::FILE* file = nullptr;
    if (fopen_s(&file, path, "ab") == 0 && file != nullptr) {
#else
    if (std::FILE* file = std::fopen(path, "ab")) {
#endif
        std::fwrite(text.data(), 1, text.size(), file);
        std::fclose(file);
    }
}

void crash_printf(const char* path, const char* format, ...) noexcept {
    std::array<char, 2048> buffer{};
    va_list args;
    va_start(args, format);
    const int written = std::vsnprintf(buffer.data(), buffer.size(), format, args);
    va_end(args);
    if (written <= 0) {
        return;
    }
    const auto count = static_cast<std::size_t>(
        written < static_cast<int>(buffer.size()) ? written : static_cast<int>(buffer.size() - 1));
    write_file_text(path, {buffer.data(), count});
}

#ifdef _WIN32

constexpr const char* kCrashLogPath = "crashes\\peelf_viewer_crash.log";
LONG g_dump_in_progress = 0;

const char* exception_code_name(DWORD code) noexcept {
    switch (code) {
        case EXCEPTION_ACCESS_VIOLATION: return "EXCEPTION_ACCESS_VIOLATION";
        case EXCEPTION_ARRAY_BOUNDS_EXCEEDED: return "EXCEPTION_ARRAY_BOUNDS_EXCEEDED";
        case EXCEPTION_BREAKPOINT: return "EXCEPTION_BREAKPOINT";
        case EXCEPTION_DATATYPE_MISALIGNMENT: return "EXCEPTION_DATATYPE_MISALIGNMENT";
        case EXCEPTION_FLT_DIVIDE_BY_ZERO: return "EXCEPTION_FLT_DIVIDE_BY_ZERO";
        case EXCEPTION_ILLEGAL_INSTRUCTION: return "EXCEPTION_ILLEGAL_INSTRUCTION";
        case EXCEPTION_IN_PAGE_ERROR: return "EXCEPTION_IN_PAGE_ERROR";
        case EXCEPTION_INT_DIVIDE_BY_ZERO: return "EXCEPTION_INT_DIVIDE_BY_ZERO";
        case EXCEPTION_STACK_OVERFLOW: return "EXCEPTION_STACK_OVERFLOW";
        default: return "UNKNOWN_SEH_EXCEPTION";
    }
}

void ensure_crash_directory() noexcept {
    CreateDirectoryW(L"crashes", nullptr);
}

std::wstring make_dump_path() noexcept {
    ensure_crash_directory();
    SYSTEMTIME local_time{};
    GetLocalTime(&local_time);

    wchar_t path[MAX_PATH]{};
    std::swprintf(path,
                  sizeof(path) / sizeof(path[0]),
                  L"crashes\\peelf_viewer-%04hu%02hu%02hu-%02hu%02hu%02hu-p%lu-t%lu.dmp",
                  local_time.wYear,
                  local_time.wMonth,
                  local_time.wDay,
                  local_time.wHour,
                  local_time.wMinute,
                  local_time.wSecond,
                  GetCurrentProcessId(),
                  GetCurrentThreadId());
    return path;
}

void print_stack_trace_addresses() noexcept {
    void* frames[64]{};
    const USHORT frame_count = CaptureStackBackTrace(0, 64, frames, nullptr);
    crash_printf(kCrashLogPath, "Stack trace addresses (%hu frames):\n", frame_count);
    for (USHORT i = 0; i < frame_count; ++i) {
        crash_printf(kCrashLogPath, "  #%02hu %p\n", i, frames[i]);
    }
}

bool write_minidump(EXCEPTION_POINTERS* exception_pointers) noexcept {
    if (InterlockedCompareExchange(&g_dump_in_progress, 1, 0) != 0) {
        crash_printf(kCrashLogPath, "MiniDumpWriteDump skipped: another dump is already in progress\n");
        return false;
    }

    const std::wstring dump_path = make_dump_path();
    HANDLE dump_file = CreateFileW(dump_path.c_str(),
                                   GENERIC_WRITE,
                                   FILE_SHARE_READ,
                                   nullptr,
                                   CREATE_ALWAYS,
                                   FILE_ATTRIBUTE_NORMAL,
                                   nullptr);
    if (dump_file == INVALID_HANDLE_VALUE) {
        crash_printf(kCrashLogPath, "MiniDumpWriteDump skipped: CreateFileW failed with %lu\n", GetLastError());
        InterlockedExchange(&g_dump_in_progress, 0);
        return false;
    }

    MINIDUMP_EXCEPTION_INFORMATION exception_info{};
    exception_info.ThreadId = GetCurrentThreadId();
    exception_info.ExceptionPointers = exception_pointers;
    exception_info.ClientPointers = TRUE;

    const MINIDUMP_TYPE dump_type = static_cast<MINIDUMP_TYPE>(
        MiniDumpWithDataSegs |
        MiniDumpWithHandleData |
        MiniDumpWithThreadInfo |
        MiniDumpWithUnloadedModules |
        MiniDumpWithIndirectlyReferencedMemory);

    const BOOL ok = MiniDumpWriteDump(GetCurrentProcess(),
                                      GetCurrentProcessId(),
                                      dump_file,
                                      dump_type,
                                      exception_pointers != nullptr ? &exception_info : nullptr,
                                      nullptr,
                                      nullptr);
    const DWORD error = GetLastError();
    CloseHandle(dump_file);
    InterlockedExchange(&g_dump_in_progress, 0);

    crash_printf(kCrashLogPath,
                 "Minidump: %ls (%s, GetLastError=%lu)\n",
                 dump_path.c_str(),
                 ok ? "written" : "failed",
                 ok ? 0UL : error);
    return ok == TRUE;
}

void print_windows_context(const CONTEXT* context) noexcept {
    if (context == nullptr) {
        return;
    }
#if defined(_M_X64)
    crash_printf(kCrashLogPath,
                 "RIP=%016llX RSP=%016llX RBP=%016llX\n"
                 "RAX=%016llX RBX=%016llX RCX=%016llX RDX=%016llX\n"
                 "RSI=%016llX RDI=%016llX R8 =%016llX R9 =%016llX\n",
                 static_cast<unsigned long long>(context->Rip),
                 static_cast<unsigned long long>(context->Rsp),
                 static_cast<unsigned long long>(context->Rbp),
                 static_cast<unsigned long long>(context->Rax),
                 static_cast<unsigned long long>(context->Rbx),
                 static_cast<unsigned long long>(context->Rcx),
                 static_cast<unsigned long long>(context->Rdx),
                 static_cast<unsigned long long>(context->Rsi),
                 static_cast<unsigned long long>(context->Rdi),
                 static_cast<unsigned long long>(context->R8),
                 static_cast<unsigned long long>(context->R9));
#endif
}

void print_current_exception() noexcept {
    try {
        throw;
    } catch (const std::exception& e) {
        crash_printf(kCrashLogPath, "Unhandled C++ exception: %s\n", e.what());
    } catch (...) {
        crash_printf(kCrashLogPath, "Unhandled non-standard C++ exception\n");
    }
}

[[noreturn]] void terminate_handler() noexcept {
    ensure_crash_directory();
    crash_printf(kCrashLogPath, "\n==== PE/ELF Viewer fatal diagnostic ====\nstd::terminate was called\n");
    if (std::current_exception()) {
        print_current_exception();
    } else {
        crash_printf(kCrashLogPath, "No active C++ exception was available.\n");
    }
    write_minidump(nullptr);
    std::_Exit(3);
}

const char* signal_name(int signal) noexcept {
    switch (signal) {
        case SIGABRT: return "SIGABRT";
        case SIGSEGV: return "SIGSEGV";
#ifdef SIGILL
        case SIGILL: return "SIGILL";
#endif
#ifdef SIGFPE
        case SIGFPE: return "SIGFPE";
#endif
        default: return "unknown";
    }
}

void signal_handler(int signal) noexcept {
    ensure_crash_directory();
    crash_printf(kCrashLogPath,
                 "\n==== PE/ELF Viewer fatal diagnostic ====\nFatal C signal received: %d (%s)\n",
                 signal,
                 signal_name(signal));
    print_stack_trace_addresses();
    write_minidump(nullptr);
    std::_Exit(128 + signal);
}

LONG WINAPI unhandled_exception_filter(EXCEPTION_POINTERS* pointers) noexcept {
    ensure_crash_directory();
    crash_printf(kCrashLogPath, "\n==== PE/ELF Viewer fatal diagnostic ====\nUnhandled Windows structured exception\n");
    if (pointers != nullptr && pointers->ExceptionRecord != nullptr) {
        const EXCEPTION_RECORD& record = *pointers->ExceptionRecord;
        crash_printf(kCrashLogPath,
                     "Code: 0x%08lX (%s)\nFault address: %p\n",
                     record.ExceptionCode,
                     exception_code_name(record.ExceptionCode),
                     record.ExceptionAddress);
        if (record.ExceptionCode == EXCEPTION_ACCESS_VIOLATION && record.NumberParameters >= 2) {
            const ULONG_PTR operation = record.ExceptionInformation[0];
            const ULONG_PTR address = record.ExceptionInformation[1];
            const char* op = operation == 0 ? "read" : (operation == 1 ? "write" : "execute");
            crash_printf(kCrashLogPath, "Access violation attempting to %s address 0x%p\n", op, reinterpret_cast<void*>(address));
        }
    }
    if (pointers != nullptr) {
        print_windows_context(pointers->ContextRecord);
    }
    print_stack_trace_addresses();
    write_minidump(pointers);
    return EXCEPTION_EXECUTE_HANDLER;
}

int crt_report_hook(int report_type, char* message, int* return_value) noexcept {
    const char* type = report_type == _CRT_ASSERT ? "CRT assert" :
                       report_type == _CRT_ERROR ? "CRT error" :
                       report_type == _CRT_WARN ? "CRT warning" : "CRT report";
    ensure_crash_directory();
    crash_printf(kCrashLogPath, "\n==== PE/ELF Viewer CRT diagnostic ====\n%s\n", type);
    if (message != nullptr) {
        crash_printf(kCrashLogPath, "%s%s", message, message[0] != '\0' && message[std::strlen(message) - 1] == '\n' ? "" : "\n");
    }
    print_stack_trace_addresses();
    if (return_value != nullptr) {
        *return_value = 0;
    }
    return FALSE;
}

void invalid_parameter_handler(const wchar_t* expression,
                               const wchar_t* function,
                               const wchar_t* file,
                               unsigned int line,
                               uintptr_t /*reserved*/) noexcept {
    ensure_crash_directory();
    crash_printf(kCrashLogPath, "\n==== PE/ELF Viewer fatal diagnostic ====\nMSVC invalid parameter handler was called\n");
    crash_printf(kCrashLogPath, "Line: %u\n", line);
    if (expression != nullptr) {
        crash_printf(kCrashLogPath, "Expression: %ls\n", expression);
    }
    if (function != nullptr) {
        crash_printf(kCrashLogPath, "Function: %ls\n", function);
    }
    if (file != nullptr) {
        crash_printf(kCrashLogPath, "File: %ls\n", file);
    }
    print_stack_trace_addresses();
    write_minidump(nullptr);
    std::_Exit(4);
}

void purecall_handler() noexcept {
    ensure_crash_directory();
    crash_printf(kCrashLogPath, "\n==== PE/ELF Viewer fatal diagnostic ====\nPure virtual function call\n");
    print_stack_trace_addresses();
    write_minidump(nullptr);
    std::_Exit(5);
}

#else

constexpr const char* kCrashLogPath = "crashes/peelf_viewer_crash.log";

void ensure_crash_directory() noexcept {
    mkdir("crashes", 0755);
}

void enable_core_dumps() noexcept {
    rlimit limit{};
    limit.rlim_cur = RLIM_INFINITY;
    limit.rlim_max = RLIM_INFINITY;
    setrlimit(RLIMIT_CORE, &limit);
}

const char* signal_name(int signal) noexcept {
    switch (signal) {
        case SIGABRT: return "SIGABRT";
        case SIGSEGV: return "SIGSEGV";
        case SIGILL: return "SIGILL";
        case SIGFPE: return "SIGFPE";
        case SIGBUS: return "SIGBUS";
        default: return "unknown";
    }
}

void write_backtrace() noexcept {
    void* frames[64]{};
    const int frame_count = backtrace(frames, 64);
    crash_printf(kCrashLogPath, "Backtrace (%d frames):\n", frame_count);
    const int fd = open(kCrashLogPath, O_CREAT | O_WRONLY | O_APPEND, 0644);
    if (fd >= 0) {
        backtrace_symbols_fd(frames, frame_count, fd);
        close(fd);
    }
}

void signal_handler(int signal, siginfo_t* info, void* /*context*/) noexcept {
    ensure_crash_directory();
    crash_printf(kCrashLogPath,
                 "\n==== PE/ELF Viewer fatal diagnostic ====\nFatal POSIX signal: %d (%s)\nAddress: %p\n",
                 signal,
                 signal_name(signal),
                 info != nullptr ? info->si_addr : nullptr);
    write_backtrace();

    struct sigaction action {};
    action.sa_handler = SIG_DFL;
    sigemptyset(&action.sa_mask);
    sigaction(signal, &action, nullptr);
    raise(signal);
}

void install_signal_handler(int signal) noexcept {
    struct sigaction action {};
    action.sa_sigaction = signal_handler;
    sigemptyset(&action.sa_mask);
    action.sa_flags = SA_SIGINFO | SA_RESETHAND;
    sigaction(signal, &action, nullptr);
}

[[noreturn]] void terminate_handler() noexcept {
    ensure_crash_directory();
    crash_printf(kCrashLogPath, "\n==== PE/ELF Viewer fatal diagnostic ====\nstd::terminate was called\n");
    if (std::current_exception()) {
        try {
            throw;
        } catch (const std::exception& e) {
            crash_printf(kCrashLogPath, "Unhandled C++ exception: %s\n", e.what());
        } catch (...) {
            crash_printf(kCrashLogPath, "Unhandled non-standard C++ exception\n");
        }
    }
    write_backtrace();
    std::abort();
}

#endif

} // namespace

void install_crash_handlers() noexcept {
    ensure_crash_directory();
    std::set_terminate(terminate_handler);

#ifdef _WIN32
    SetUnhandledExceptionFilter(unhandled_exception_filter);
    _CrtSetReportHook(crt_report_hook);
    _set_invalid_parameter_handler(invalid_parameter_handler);
    _set_purecall_handler(purecall_handler);
    _set_abort_behavior(0, _WRITE_ABORT_MSG | _CALL_REPORTFAULT);
    std::signal(SIGABRT, signal_handler);
#ifdef SIGILL
    std::signal(SIGILL, signal_handler);
#endif
#ifdef SIGFPE
    std::signal(SIGFPE, signal_handler);
#endif
#else
    enable_core_dumps();
    install_signal_handler(SIGABRT);
    install_signal_handler(SIGSEGV);
    install_signal_handler(SIGILL);
    install_signal_handler(SIGFPE);
    install_signal_handler(SIGBUS);
#endif
}

} // namespace viewer::crash
