#include "application.h"

#include <cstdarg>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <exception>
#include <string_view>

#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <crtdbg.h>
#include <cstdlib>
#include <windows.h>
#endif

namespace {

#ifdef _WIN32
void print_stack_trace_addresses() noexcept;
void write_stderr(std::string_view text) noexcept;
void diagnostic_printf(const char* format, ...) noexcept;

int crt_report_hook(int report_type, char* message, int* return_value) noexcept {
    const char* type = "CRT report";
    switch (report_type) {
        case _CRT_ASSERT:
            type = "CRT assert";
            break;
        case _CRT_ERROR:
            type = "CRT error";
            break;
        case _CRT_WARN:
            type = "CRT warning";
            break;
        default:
            break;
    }

    write_stderr("\n==== PE/ELF Viewer CRT diagnostic ====\n");
    diagnostic_printf("%s\n", type);
    if (message != nullptr) {
        write_stderr(message);
        const std::string_view text{message};
        if (text.empty() || text.back() != '\n') {
            write_stderr("\n");
        }
    }
    print_stack_trace_addresses();
    if (return_value != nullptr) {
        *return_value = 0;
    }
    return FALSE;
}
#endif

void write_stderr(std::string_view text) noexcept {
    std::fwrite(text.data(), 1, text.size(), stderr);
    std::fflush(stderr);

#ifdef _WIN32
    std::FILE* file = nullptr;
    if (fopen_s(&file, "peelf_viewer_crash.log", "ab") == 0 && file != nullptr) {
#else
    if (std::FILE* file = std::fopen("peelf_viewer_crash.log", "ab")) {
#endif
        std::fwrite(text.data(), 1, text.size(), file);
        std::fclose(file);
    }
}

void diagnostic_printf(const char* format, ...) noexcept {
    char buffer[2048]{};
    va_list args;
    va_start(args, format);
    const int written = std::vsnprintf(buffer, sizeof(buffer), format, args);
    va_end(args);
    if (written <= 0) {
        return;
    }

    const std::size_t count = static_cast<std::size_t>(
        written < static_cast<int>(sizeof(buffer)) ? written : static_cast<int>(sizeof(buffer) - 1));
    write_stderr({buffer, count});
}

void print_fatal_prefix(std::string_view reason) noexcept {
    write_stderr("\n==== PE/ELF Viewer fatal diagnostic ====\n");
    write_stderr(reason);
    write_stderr("\n");
}

void print_current_exception() noexcept {
    try {
        throw;
    } catch (const std::exception& e) {
        diagnostic_printf("Unhandled C++ exception: %s\n", e.what());
    } catch (...) {
        write_stderr("Unhandled non-standard C++ exception\n");
    }
}

[[noreturn]] void terminate_handler() noexcept {
    print_fatal_prefix("std::terminate was called");
    if (std::current_exception()) {
        print_current_exception();
    } else {
        write_stderr("No active C++ exception was available.\n");
    }
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
    print_fatal_prefix("Fatal C signal received");
    diagnostic_printf("Signal: %d (%s)\n", signal, signal_name(signal));
#ifdef _WIN32
    print_stack_trace_addresses();
#endif
    std::_Exit(128 + signal);
}

#ifdef _WIN32
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

void print_windows_context(const CONTEXT* context) noexcept {
    if (context == nullptr) {
        return;
    }

#if defined(_M_X64)
    diagnostic_printf("RIP=%016llX RSP=%016llX RBP=%016llX\n"
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
#elif defined(_M_IX86)
    diagnostic_printf("EIP=%08lX ESP=%08lX EBP=%08lX\n"
                      "EAX=%08lX EBX=%08lX ECX=%08lX EDX=%08lX\n",
                      context->Eip, context->Esp, context->Ebp,
                      context->Eax, context->Ebx, context->Ecx, context->Edx);
#endif
}

void print_stack_trace_addresses() noexcept {
    void* frames[64]{};
    const USHORT frame_count = CaptureStackBackTrace(0, 64, frames, nullptr);
    diagnostic_printf("Stack trace addresses (%hu frames):\n", frame_count);
    for (USHORT i = 0; i < frame_count; ++i) {
        diagnostic_printf("  #%02hu %p\n", i, frames[i]);
    }
}

LONG WINAPI unhandled_exception_filter(EXCEPTION_POINTERS* pointers) noexcept {
    print_fatal_prefix("Unhandled Windows structured exception");
    if (pointers != nullptr && pointers->ExceptionRecord != nullptr) {
        const EXCEPTION_RECORD& record = *pointers->ExceptionRecord;
        diagnostic_printf("Code: 0x%08lX (%s)\n",
                          record.ExceptionCode, exception_code_name(record.ExceptionCode));
        diagnostic_printf("Fault address: %p\n", record.ExceptionAddress);
        if (record.ExceptionCode == EXCEPTION_ACCESS_VIOLATION &&
            record.NumberParameters >= 2) {
            const ULONG_PTR operation = record.ExceptionInformation[0];
            const ULONG_PTR address = record.ExceptionInformation[1];
            const char* op = operation == 0 ? "read" : (operation == 1 ? "write" : "execute");
            diagnostic_printf("Access violation attempting to %s address 0x%p\n",
                              op, reinterpret_cast<void*>(address));
        }
    }
    if (pointers != nullptr) {
        print_windows_context(pointers->ContextRecord);
    }
    print_stack_trace_addresses();
    return EXCEPTION_EXECUTE_HANDLER;
}

void invalid_parameter_handler(const wchar_t* expression,
                               const wchar_t* function,
                               const wchar_t* file,
                               unsigned int line,
                               uintptr_t /*reserved*/) noexcept {
    print_fatal_prefix("MSVC invalid parameter handler was called");
    if (expression != nullptr) {
        std::fwprintf(stderr, L"Expression: %ls\n", expression);
    }
    if (function != nullptr) {
        std::fwprintf(stderr, L"Function: %ls\n", function);
    }
    if (file != nullptr) {
        std::fwprintf(stderr, L"File: %ls\n", file);
    }
    diagnostic_printf("Line: %u\n", line);
    print_stack_trace_addresses();
    std::_Exit(4);
}

void purecall_handler() noexcept {
    print_fatal_prefix("Pure virtual function call");
    print_stack_trace_addresses();
    std::_Exit(5);
}
#endif

void install_fatal_diagnostics() noexcept {
    std::set_terminate(terminate_handler);
    std::signal(SIGABRT, signal_handler);
#ifndef _WIN32
    std::signal(SIGSEGV, signal_handler);
#endif
#ifdef SIGILL
    std::signal(SIGILL, signal_handler);
#endif
#ifdef SIGFPE
    std::signal(SIGFPE, signal_handler);
#endif
#ifdef _WIN32
    SetUnhandledExceptionFilter(unhandled_exception_filter);
    _CrtSetReportHook(crt_report_hook);
    _set_invalid_parameter_handler(invalid_parameter_handler);
    _set_purecall_handler(purecall_handler);
    _set_abort_behavior(0, _WRITE_ABORT_MSG | _CALL_REPORTFAULT);
#endif
}

}  // namespace

int main() {
    install_fatal_diagnostics();

    try {
        viewer::Application app;
        viewer::AppConfig config{};
        config.title = "PE/ELF Viewer";
        config.width = 1280;
        config.height = 720;

        app.init(config);
        app.run();
        app.shutdown();
    } catch (const std::exception& e) {
        print_fatal_prefix("Caught top-level C++ exception");
        diagnostic_printf("Fatal error: %s\n", e.what());
        return 1;
    } catch (...) {
        print_fatal_prefix("Caught top-level non-standard C++ exception");
        return 1;
    }

    return 0;
}
