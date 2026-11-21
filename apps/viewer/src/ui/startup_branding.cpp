#include "startup_branding.hpp"

#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <objidl.h>
#include <gdiplus.h>
#define GLFW_INCLUDE_NONE
#include <GLFW/glfw3.h>
#define GLFW_EXPOSE_NATIVE_WIN32
#include <GLFW/glfw3native.h>
#include <algorithm>
#include <future>
#include <thread>

namespace viewer {
struct StartupSplash::Impl {
    std::thread thread;
    HWND window{};
    Gdiplus::Image* image{};
    ULONGLONG started{};

    static LRESULT CALLBACK procedure(HWND hwnd, UINT message, WPARAM wp, LPARAM lp) {
        auto* self = reinterpret_cast<Impl*>(GetWindowLongPtrW(hwnd, GWLP_USERDATA));
        if (message == WM_NCCREATE) {
            self = static_cast<Impl*>(reinterpret_cast<CREATESTRUCTW*>(lp)->lpCreateParams);
            SetWindowLongPtrW(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(self));
        }
        if (message == WM_PAINT && self) {
            PAINTSTRUCT paint{};
            HDC dc = BeginPaint(hwnd, &paint);
            RECT area{};
            GetClientRect(hwnd, &area);
            Gdiplus::Graphics graphics(dc);
            graphics.Clear(Gdiplus::Color(255, 16, 23, 36));
            const float width = static_cast<float>(area.right);
            const float size = width;
            if (self->image) {
                graphics.SetInterpolationMode(Gdiplus::InterpolationModeHighQualityBicubic);
                graphics.DrawImage(self->image, 0.0f, 0.0f, size, size);
            }
            Gdiplus::FontFamily family(L"Segoe UI");
            Gdiplus::Font title(&family, width * 0.041f, Gdiplus::FontStyleBold, Gdiplus::UnitPixel);
            Gdiplus::Font detail(&family, width * 0.027f, Gdiplus::FontStyleRegular, Gdiplus::UnitPixel);
            Gdiplus::SolidBrush white(Gdiplus::Color(255, 231, 240, 255));
            Gdiplus::SolidBrush cyan(Gdiplus::Color(255, 100, 215, 245));
            Gdiplus::StringFormat format;
            format.SetAlignment(Gdiplus::StringAlignmentCenter);
            auto line = [&](const wchar_t* text, Gdiplus::Font& font, float y, Gdiplus::Brush& brush) {
                graphics.DrawString(text, -1, &font, Gdiplus::RectF(0, y, width, width * .06f), &format, &brush);
            };
            line(L"PE / ELF Explorer", title, size, white);
            line(L"x86 / X64  ·  ARM32 / ARM64  ·  RISC-V32 / 64", detail, size + width * .065f, cyan);
            line(L"MIPS32 / 64  ·  PowerPC32 / 64", detail, size + width * .11f, cyan);
            line(L"Starting explorer…", detail, size + width * .17f, white);
            EndPaint(hwnd, &paint);
            return 0;
        }
        if (message == WM_APP && self) {
            const auto elapsed = GetTickCount64() - self->started;
            if (elapsed >= 1200) DestroyWindow(hwnd);
            else SetTimer(hwnd, 1, static_cast<UINT>(1200 - elapsed), nullptr);
            return 0;
        }
        if (message == WM_TIMER || message == WM_CLOSE) { DestroyWindow(hwnd); return 0; }
        if (message == WM_DESTROY) { PostQuitMessage(0); return 0; }
        return DefWindowProcW(hwnd, message, wp, lp);
    }

    Impl() {
        std::promise<HWND> ready;
        auto result = ready.get_future();
        thread = std::thread([this, ready = std::move(ready)]() mutable {
            ULONG_PTR token{};
            Gdiplus::GdiplusStartupInput input;
            if (Gdiplus::GdiplusStartup(&token, &input, nullptr) != Gdiplus::Ok) {
                ready.set_value(nullptr);
                return;
            }
            const auto module = GetModuleHandleW(nullptr);
            IStream* stream{};
            const auto resource = FindResourceW(module, MAKEINTRESOURCEW(102), MAKEINTRESOURCEW(10));
            if (resource) {
                const auto count = SizeofResource(module, resource);
                const auto data = LockResource(LoadResource(module, resource));
                if (data && CreateStreamOnHGlobal(nullptr, TRUE, &stream) == S_OK) {
                    stream->Write(data, count, nullptr);
                    LARGE_INTEGER zero{};
                    stream->Seek(zero, STREAM_SEEK_SET, nullptr);
                    image = Gdiplus::Image::FromStream(stream);
                }
            }
            WNDCLASSW wc{};
            wc.lpfnWndProc = procedure;
            wc.hInstance = module;
            wc.lpszClassName = L"PeelfStartupSplash";
            wc.hCursor = LoadCursorW(nullptr, MAKEINTRESOURCEW(32512));
            RegisterClassW(&wc);
            POINT cursor{};
            GetCursorPos(&cursor);
            MONITORINFO monitor{sizeof(MONITORINFO)};
            GetMonitorInfoW(MonitorFromPoint(cursor, MONITOR_DEFAULTTOPRIMARY), &monitor);
            const auto& work = monitor.rcWork;
            const int width = static_cast<int>(std::min(520L, std::min(work.right - work.left, (work.bottom - work.top) * 3 / 4)));
            const int height = width * 5 / 4;
            started = GetTickCount64();
            const auto hwnd = CreateWindowExW(WS_EX_TOOLWINDOW | WS_EX_TOPMOST | WS_EX_NOACTIVATE,
                wc.lpszClassName, L"PE / ELF Explorer", WS_POPUP,
                work.left + (work.right - work.left - width) / 2,
                work.top + (work.bottom - work.top - height) / 2,
                width, height, nullptr, nullptr, module, this);
            if (hwnd) { ShowWindow(hwnd, SW_SHOWNOACTIVATE); UpdateWindow(hwnd); }
            ready.set_value(hwnd);
            if (hwnd) {
                MSG message{};
                while (GetMessageW(&message, nullptr, 0, 0) > 0) {
                    TranslateMessage(&message);
                    DispatchMessageW(&message);
                }
            }
            delete image;
            if (stream) stream->Release();
            UnregisterClassW(wc.lpszClassName, module);
            Gdiplus::GdiplusShutdown(token);
        });
        window = result.get();
    }
    ~Impl() {
        if (window) PostMessageW(window, WM_APP, 0, 0);
        if (thread.joinable()) thread.join();
    }
};

void set_window_branding(GLFWwindow* window) {
    const auto hwnd = glfwGetWin32Window(window);
    const auto module = GetModuleHandleW(nullptr);
    // Shared resource icons remain valid for the lifetime of the process.
    for (const auto kind : {ICON_SMALL, ICON_BIG}) {
        const int size = GetSystemMetrics(kind == ICON_SMALL ? SM_CXSMICON : SM_CXICON);
        const auto icon = LoadImageW(module, MAKEINTRESOURCEW(101), IMAGE_ICON, size, size, LR_SHARED);
        if (icon) SendMessageW(hwnd, WM_SETICON, kind, reinterpret_cast<LPARAM>(icon));
    }
}
}
#else
namespace viewer {
struct StartupSplash::Impl {};
void set_window_branding(GLFWwindow*) {}
}
#endif

namespace viewer {
StartupSplash::StartupSplash() : impl_(std::make_unique<Impl>()) {}
StartupSplash::~StartupSplash() = default;
}
