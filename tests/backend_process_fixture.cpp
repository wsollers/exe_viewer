#include <chrono>
#include <cstdio>
#include <fstream>
#include <iostream>
#include <string>
#include <thread>
#include <vector>

#if defined(_WIN32)
#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <io.h>
#else
#include <unistd.h>
#endif

int main(int argc, char** argv) {
    if (argc == 3 && std::string(argv[1]) == "echo") {
        std::ofstream file(argv[2]);
        file << argv[2];
        return file ? 0 : 1;
    }
    if (argc == 2 && std::string(argv[1]) == "sleep") {
        std::this_thread::sleep_for(std::chrono::seconds(30));
        return 0;
    }
    if (argc == 2 && std::string(argv[1]) == "flood-io") {
        // Emit 512 KiB to stderr and 512 KiB to stdout BEFORE draining stdin.
        // Any caller that writes large stdin synchronously before reading pipes, or
        // drains stdout sequentially before stderr, will deadlock on pipe buffers.
        const std::string err_chunk(16384, 'E');
        const std::string out_chunk(16384, 'O');
        for (int i = 0; i < 32; ++i) {
            std::cerr.write(err_chunk.data(), static_cast<std::streamsize>(err_chunk.size()));
        }
        std::cerr.flush();
        for (int i = 0; i < 32; ++i) {
            std::cout.write(out_chunk.data(), static_cast<std::streamsize>(out_chunk.size()));
        }
        std::cout.flush();

        std::size_t stdin_total = 0;
        std::vector<char> buf(16384);
        while (std::cin.read(buf.data(), static_cast<std::streamsize>(buf.size())) ||
               std::cin.gcount() > 0) {
            stdin_total += static_cast<std::size_t>(std::cin.gcount());
            if (!std::cin) {
                break;
            }
        }
        std::cout << "\nSTDIN_BYTES=" << stdin_total << "\n";
        std::cout.flush();
        return 0;
    }
    if (argc == 2 && std::string(argv[1]) == "early-exit") {
        std::cerr << "early-err";
        std::cerr.flush();
        return 42;
    }
    if (argc == 2 && std::string(argv[1]) == "hang-after-close") {
        std::cout << "partial-out";
        std::cout.flush();
#if defined(_WIN32)
        ::_close(1);
        ::_close(2);
#else
        ::close(STDOUT_FILENO);
        ::close(STDERR_FILENO);
#endif
        std::this_thread::sleep_for(std::chrono::seconds(30));
        return 0;
    }
    if (argc >= 2 && std::string(argv[1]) == "echo-stdio") {
        std::string in_data((std::istreambuf_iterator<char>(std::cin)),
                            std::istreambuf_iterator<char>());
        std::cout << "OUT:" << in_data;
        std::cout.flush();
        if (argc >= 3) {
            std::cerr << "ERR:" << argv[2];
            std::cerr.flush();
        }
        return 0;
    }
    if (argc == 2 && std::string(argv[1]) == "spawn-grandchild-hold") {
        std::cout << "parent-done";
        std::cout.flush();
        std::cerr << "parent-err";
        std::cerr.flush();
#if defined(_WIN32)
        wchar_t self_path[MAX_PATH]{};
        const DWORD len = ::GetModuleFileNameW(nullptr, self_path, MAX_PATH);
        if (len == 0 || len >= MAX_PATH) {
            return 2;
        }
        std::wstring cmd = L"\"";
        cmd += self_path;
        cmd += L"\" sleep";
        STARTUPINFOW si{};
        si.cb = sizeof(si);
        si.dwFlags = STARTF_USESTDHANDLES;
        si.hStdInput = ::GetStdHandle(STD_INPUT_HANDLE);
        si.hStdOutput = ::GetStdHandle(STD_OUTPUT_HANDLE);
        si.hStdError = ::GetStdHandle(STD_ERROR_HANDLE);
        PROCESS_INFORMATION pi{};
        if (!::CreateProcessW(self_path,
                              cmd.data(),
                              nullptr,
                              nullptr,
                              TRUE,
                              CREATE_NO_WINDOW,
                              nullptr,
                              nullptr,
                              &si,
                              &pi)) {
            return 3;
        }
        ::CloseHandle(pi.hThread);
        ::CloseHandle(pi.hProcess);
        return 0;
#else
        const pid_t gc = ::fork();
        if (gc < 0) {
            return 3;
        }
        if (gc == 0) {
            std::this_thread::sleep_for(std::chrono::seconds(30));
            _exit(0);
        }
        return 0;
#endif
    }
    return 7;
}
