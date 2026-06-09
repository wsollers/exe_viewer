#include "symbols/debug_symbols.hpp"

#include <algorithm>
#include <array>
#include <cctype>
#include <filesystem>
#include <fstream>
#include <limits>
#include <sstream>
#include <string>
#include <string_view>

#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>
#include <Objbase.h>
#include <Unknwn.h>
#ifdef PEELF_HAS_DIA
#include <dia2.h>
#endif
#endif

namespace viewer {
namespace {

[[nodiscard]] bool has_pdb_extension(const std::filesystem::path& path) {
    std::string ext = path.extension().string();
    std::ranges::transform(ext, ext.begin(), [](unsigned char c) {
        return static_cast<char>(std::tolower(c));
    });
    return ext == ".pdb";
}

[[nodiscard]] bool has_native_pdb_signature(const std::filesystem::path& path) {
    std::ifstream file(path, std::ios::binary);
    if (!file) {
        return false;
    }

    std::array<char, 32> signature{};
    file.read(signature.data(), static_cast<std::streamsize>(signature.size()));
    const std::string_view bytes(signature.data(), static_cast<std::size_t>(file.gcount()));
    return bytes.starts_with("Microsoft C/C++ MSF 7.00") ||
           bytes.starts_with("Microsoft C/C++ program database");
}

[[nodiscard]] std::uint64_t estimate_pe_image_base(const peelf::IBinaryImage& image) noexcept {
    if (image.format() != peelf::Format::PE || image.sections().empty()) {
        return 0;
    }

    std::uint64_t minimum_va = std::numeric_limits<std::uint64_t>::max();
    for (const peelf::Section& section : image.sections()) {
        if (section.virtual_address != 0) {
            minimum_va = std::min(minimum_va, section.virtual_address);
        }
    }
    if (minimum_va == std::numeric_limits<std::uint64_t>::max()) {
        return 0;
    }

    constexpr std::uint64_t kPeImageBaseAlignment = 0x10000u;
    return minimum_va & ~(kPeImageBaseAlignment - 1u);
}

#if defined(_WIN32) && defined(PEELF_HAS_DIA)
template <typename T>
class ComPtr {
public:
    ComPtr() = default;
    ~ComPtr() { reset(); }

    ComPtr(const ComPtr&) = delete;
    ComPtr& operator=(const ComPtr&) = delete;
    ComPtr(ComPtr&& other) noexcept
        : ptr_(std::exchange(other.ptr_, nullptr)) {}
    ComPtr& operator=(ComPtr&& other) noexcept {
        if (this != &other) {
            reset();
            ptr_ = std::exchange(other.ptr_, nullptr);
        }
        return *this;
    }

    [[nodiscard]] T* get() const noexcept { return ptr_; }
    [[nodiscard]] T** put() noexcept {
        reset();
        return &ptr_;
    }
    [[nodiscard]] T* operator->() const noexcept { return ptr_; }
    explicit operator bool() const noexcept { return ptr_ != nullptr; }

    void reset() noexcept {
        if (ptr_ != nullptr) {
            ptr_->Release();
            ptr_ = nullptr;
        }
    }

private:
    T* ptr_ = nullptr;
};

class Bstr {
public:
    ~Bstr() { reset(); }
    Bstr(const Bstr&) = delete;
    Bstr& operator=(const Bstr&) = delete;
    Bstr() = default;

    [[nodiscard]] BSTR* put() noexcept {
        reset();
        return &value_;
    }
    [[nodiscard]] BSTR get() const noexcept { return value_; }

    void reset() noexcept {
        if (value_ != nullptr) {
            SysFreeString(value_);
            value_ = nullptr;
        }
    }

private:
    BSTR value_ = nullptr;
};

[[nodiscard]] std::wstring to_wstring(const std::filesystem::path& path) {
    return path.wstring();
}

[[nodiscard]] std::string to_utf8(BSTR value) {
    if (value == nullptr) {
        return {};
    }
    const int wide_length = static_cast<int>(SysStringLen(value));
    if (wide_length == 0) {
        return {};
    }
    const int utf8_length = WideCharToMultiByte(CP_UTF8, 0, value, wide_length, nullptr, 0, nullptr, nullptr);
    if (utf8_length <= 0) {
        return {};
    }
    std::string out(static_cast<std::size_t>(utf8_length), '\0');
    WideCharToMultiByte(CP_UTF8, 0, value, wide_length, out.data(), utf8_length, nullptr, nullptr);
    return out;
}

[[nodiscard]] std::string format_hresult(HRESULT hr) {
    std::ostringstream out;
    out << "0x" << std::hex << std::uppercase << static_cast<unsigned long>(hr);
    return out.str();
}

[[nodiscard]] std::string last_error_message(std::string_view operation) {
    return std::string(operation) + " failed with Win32 error " + std::to_string(GetLastError());
}

using DllGetClassObjectFn = HRESULT(STDAPICALLTYPE*)(REFCLSID, REFIID, LPVOID*);

[[nodiscard]] bool create_dia_source_from_dll(ComPtr<IDiaDataSource>& source,
                                              HMODULE& module,
                                              std::string& diagnostic) {
#ifdef PEELF_DIA_DLL_PATH
    const std::filesystem::path dll_path(PEELF_DIA_DLL_PATH);
    HMODULE loaded = LoadLibraryW(dll_path.wstring().c_str());
    if (loaded == nullptr) {
        diagnostic = last_error_message("LoadLibraryW(" + dll_path.string() + ")");
        return false;
    }

    const auto get_class_object = reinterpret_cast<DllGetClassObjectFn>(GetProcAddress(loaded, "DllGetClassObject"));
    if (get_class_object == nullptr) {
        diagnostic = last_error_message("GetProcAddress(DllGetClassObject)");
        FreeLibrary(loaded);
        return false;
    }

    ComPtr<IClassFactory> factory;
    HRESULT hr = get_class_object(__uuidof(DiaSource), __uuidof(IClassFactory),
                                  reinterpret_cast<void**>(factory.put()));
    if (FAILED(hr) || !factory) {
        diagnostic = "DllGetClassObject for DiaSource failed with HRESULT " + format_hresult(hr);
        FreeLibrary(loaded);
        return false;
    }

    hr = factory->CreateInstance(nullptr, __uuidof(IDiaDataSource), reinterpret_cast<void**>(source.put()));
    if (FAILED(hr) || !source) {
        diagnostic = "DIA class factory CreateInstance failed with HRESULT " + format_hresult(hr);
        FreeLibrary(loaded);
        return false;
    }

    module = loaded;
    diagnostic = "loaded DIA from " + dll_path.string();
    return true;
#else
    (void)source;
    (void)module;
    diagnostic = "PEELF_DIA_DLL_PATH was not configured";
    return false;
#endif
}

[[nodiscard]] bool create_dia_source(ComPtr<IDiaDataSource>& source,
                                     HMODULE& module,
                                     std::string& diagnostic) {
    HRESULT hr = CoCreateInstance(__uuidof(DiaSource), nullptr, CLSCTX_INPROC_SERVER,
                                  __uuidof(IDiaDataSource), reinterpret_cast<void**>(source.put()));
    if (SUCCEEDED(hr) && source) {
        diagnostic = "loaded registered DIA COM source";
        return true;
    }

    const std::string registered_failure =
        "registered DIA COM source failed with HRESULT " + format_hresult(hr);
    std::string dll_failure;
    if (create_dia_source_from_dll(source, module, dll_failure)) {
        return true;
    }

    diagnostic = registered_failure + "; " + dll_failure;
    return false;
}

void add_dia_children(IDiaSymbol& global,
                      enum SymTagEnum tag,
                      std::uint64_t image_base,
                      bool function,
                      std::vector<DebugSymbol>& out) {
    ComPtr<IDiaEnumSymbols> symbols;
    if (FAILED(global.findChildren(tag, nullptr, nsNone, symbols.put())) || !symbols) {
        return;
    }

    ComPtr<IDiaSymbol> symbol;
    ULONG fetched = 0;
    while (SUCCEEDED(symbols->Next(1, symbol.put(), &fetched)) && fetched == 1) {
        DWORD rva = 0;
        if (FAILED(symbol->get_relativeVirtualAddress(&rva)) || rva == 0) {
            symbol.reset();
            continue;
        }

        Bstr name;
        if (FAILED(symbol->get_name(name.put())) || name.get() == nullptr) {
            symbol.reset();
            continue;
        }

        ULONGLONG length = 0;
        if (FAILED(symbol->get_length(&length))) {
            length = 0;
        }

        out.push_back(DebugSymbol{
            .name = to_utf8(name.get()),
            .relative_virtual_address = rva,
            .virtual_address = image_base + rva,
            .size = static_cast<std::uint64_t>(length),
            .function = function,
        });
        symbol.reset();
    }
}
#endif

} // namespace

const char* to_string(DebugSymbolLoadStatus status) noexcept {
    switch (status) {
        case DebugSymbolLoadStatus::Loaded:
            return "loaded";
        case DebugSymbolLoadStatus::FileNotFound:
            return "file not found";
        case DebugSymbolLoadStatus::UnsupportedFormat:
            return "unsupported format";
        case DebugSymbolLoadStatus::BackendUnavailable:
            return "backend unavailable";
        case DebugSymbolLoadStatus::BackendError:
            return "backend error";
    }
    return "unknown";
}

std::optional<std::filesystem::path> find_local_codeview_pdb(const peelf::IBinaryImage& image,
                                                            const std::filesystem::path& image_path) {
    for (const peelf::PeDebugDirectory& debug : image.pe_debug_directories()) {
        if (debug.codeview_pdb_path.empty()) {
            continue;
        }

        std::filesystem::path pdb_path(debug.codeview_pdb_path);
        if (pdb_path.is_absolute() && std::filesystem::exists(pdb_path)) {
            return pdb_path;
        }

        const std::filesystem::path sibling = image_path.parent_path() / pdb_path.filename();
        if (std::filesystem::exists(sibling)) {
            return sibling;
        }
    }
    return std::nullopt;
}

DebugSymbolLoadResult load_pdb_debug_symbols(const std::filesystem::path& pdb_path,
                                             const peelf::IBinaryImage& image) {
    if (!has_pdb_extension(pdb_path)) {
        return DebugSymbolLoadResult{
            .status = DebugSymbolLoadStatus::UnsupportedFormat,
            .diagnostic = "Only PDB debug symbol files are supported by this loader",
        };
    }
    if (!std::filesystem::exists(pdb_path)) {
        return DebugSymbolLoadResult{
            .status = DebugSymbolLoadStatus::FileNotFound,
            .diagnostic = pdb_path.string(),
        };
    }
    if (!has_native_pdb_signature(pdb_path)) {
        return DebugSymbolLoadResult{
            .status = DebugSymbolLoadStatus::UnsupportedFormat,
            .diagnostic = "File does not have a recognized native PDB/MSF signature",
        };
    }

#if defined(_WIN32) && defined(PEELF_HAS_DIA)
    const HRESULT init_result = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
    const bool should_uninitialize = SUCCEEDED(init_result);
    if (FAILED(init_result) && init_result != RPC_E_CHANGED_MODE) {
        return DebugSymbolLoadResult{
            .status = DebugSymbolLoadStatus::BackendError,
            .diagnostic = "CoInitializeEx failed",
        };
    }

    ComPtr<IDiaDataSource> source;
    ComPtr<IDiaSession> session;
    ComPtr<IDiaSymbol> global;
    HMODULE dia_module = nullptr;
    const auto cleanup_com = [&]() noexcept {
        global.reset();
        session.reset();
        source.reset();
        if (dia_module != nullptr) {
            FreeLibrary(dia_module);
            dia_module = nullptr;
        }
        if (should_uninitialize) {
            CoUninitialize();
        }
    };

    std::string source_diagnostic;
    if (!create_dia_source(source, dia_module, source_diagnostic)) {
        cleanup_com();
        return DebugSymbolLoadResult{
            .status = DebugSymbolLoadStatus::BackendUnavailable,
            .diagnostic = "DIA source is unavailable: " + source_diagnostic,
        };
    }

    const std::wstring wide_path = to_wstring(pdb_path);
    HRESULT hr = source->loadDataFromPdb(wide_path.c_str());
    if (FAILED(hr)) {
        cleanup_com();
        return DebugSymbolLoadResult{
            .status = DebugSymbolLoadStatus::BackendError,
            .diagnostic = "DIA could not load the PDB",
        };
    }

    hr = source->openSession(session.put());
    if (FAILED(hr) || !session) {
        cleanup_com();
        return DebugSymbolLoadResult{
            .status = DebugSymbolLoadStatus::BackendError,
            .diagnostic = "DIA could not open a PDB session",
        };
    }

    hr = session->get_globalScope(global.put());
    if (FAILED(hr) || !global) {
        cleanup_com();
        return DebugSymbolLoadResult{
            .status = DebugSymbolLoadStatus::BackendError,
            .diagnostic = "DIA could not read the PDB global scope",
        };
    }

    const std::uint64_t image_base = estimate_pe_image_base(image);
    DebugSymbolLoadResult result;
    add_dia_children(*global.get(), SymTagFunction, image_base, true, result.symbols);
    add_dia_children(*global.get(), SymTagPublicSymbol, image_base, false, result.symbols);

    std::ranges::sort(result.symbols, {}, &DebugSymbol::name);
    result.symbols.erase(std::ranges::unique(result.symbols, [](const DebugSymbol& lhs, const DebugSymbol& rhs) {
        return lhs.name == rhs.name && lhs.virtual_address == rhs.virtual_address;
    }).begin(), result.symbols.end());

    result.status = DebugSymbolLoadStatus::Loaded;
    result.diagnostic = pdb_path.string();

    cleanup_com();
    return result;
#else
    (void)image;
    return DebugSymbolLoadResult{
        .status = DebugSymbolLoadStatus::BackendUnavailable,
        .diagnostic = "PDB loading requires the Windows DIA SDK backend",
    };
#endif
}

} // namespace viewer
