#include "symbols/debug_symbols.hpp"

#include <peelf/dwarf.hpp>
#include <peelf/pdb.hpp>

#include <algorithm>
#include <array>
#include <cctype>
#include <filesystem>
#include <fstream>
#include <limits>
#include <map>
#include <sstream>
#include <string>
#include <string_view>
#include <utility>

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

[[nodiscard]] bool pdb_matches_codeview_entry(const std::filesystem::path& pdb_path,
                                              const peelf::PeDebugDirectory& debug) {
    if (!has_native_pdb_signature(pdb_path)) {
        return false;
    }
    const bool has_rsds_guid = std::ranges::any_of(
        debug.codeview_guid, [](std::uint8_t b) { return b != 0u; });
    if (!has_rsds_guid) {
        return true;
    }
    const auto pdb_id = peelf::read_pdb_identity(pdb_path);
    if (!pdb_id.has_value()) {
        return false;
    }
    if (!std::ranges::equal(pdb_id->guid, debug.codeview_guid)) {
        return false;
    }
    if (debug.codeview_age != 0u) {
        const bool age_matches =
            (pdb_id->info_age == debug.codeview_age) ||
            (pdb_id->dbi_age.has_value() && *pdb_id->dbi_age == debug.codeview_age);
        if (!age_matches) {
            return false;
        }
    }
    return true;
}

[[nodiscard]] constexpr std::optional<std::uint64_t> checked_add_rva(
    std::uint64_t image_base,
    std::uint64_t rva) noexcept {
    if (rva > std::numeric_limits<std::uint64_t>::max() - image_base) {
        return std::nullopt;
    }
    return image_base + rva;
}

[[nodiscard]] std::string format_guid_hex(std::span<const std::uint8_t> guid) {
    std::string out;
    out.reserve(guid.size() * 2u);
    constexpr std::string_view kHex = "0123456789ABCDEF";
    for (const std::uint8_t b : guid) {
        out.push_back(kHex[(b >> 4u) & 0x0Fu]);
        out.push_back(kHex[b & 0x0Fu]);
    }
    return out;
}

[[nodiscard]] std::optional<std::string> validate_pdb_matches_image_codeview(
    const std::filesystem::path& pdb_path,
    const peelf::IBinaryImage& image) {
    bool has_codeview_rsds = false;
    const peelf::PeDebugDirectory* first_rsds = nullptr;
    for (const peelf::PeDebugDirectory& debug : image.pe_debug_directories()) {
        const bool has_rsds_guid = std::ranges::any_of(
            debug.codeview_guid, [](std::uint8_t b) { return b != 0u; });
        if (debug.codeview_signature != 0x5344'5352u && !has_rsds_guid) {
            continue;
        }
        has_codeview_rsds = true;
        if (first_rsds == nullptr) {
            first_rsds = &debug;
        }
        if (pdb_matches_codeview_entry(pdb_path, debug)) {
            return std::nullopt;
        }
    }

    if (!has_codeview_rsds) {
        return std::nullopt;
    }

    std::string diag = "PDB GUID/Age does not match PE CodeView RSDS debug directory: " + pdb_path.string();
    if (first_rsds != nullptr) {
        diag += " (expected GUID=" + format_guid_hex(first_rsds->codeview_guid) +
                ", age=" + std::to_string(first_rsds->codeview_age);
        if (const auto pdb_id = peelf::read_pdb_identity(pdb_path); pdb_id.has_value()) {
            diag += "; actual GUID=" + format_guid_hex(pdb_id->guid) +
                    ", info_age=" + std::to_string(pdb_id->info_age);
            if (pdb_id->dbi_age.has_value()) {
                diag += ", dbi_age=" + std::to_string(*pdb_id->dbi_age);
            }
        }
        diag.push_back(')');
    }
    return diag;
}

[[nodiscard]] std::string format_macho_uuid_canonical(std::span<const std::uint8_t, 16> uuid) {
    std::string out;
    out.reserve(36u);
    constexpr std::string_view kHex = "0123456789ABCDEF";
    for (std::size_t i = 0u; i < 16u; ++i) {
        if (i == 4u || i == 6u || i == 8u || i == 10u) {
            out.push_back('-');
        }
        out.push_back(kHex[(uuid[i] >> 4u) & 0x0Fu]);
        out.push_back(kHex[uuid[i] & 0x0Fu]);
    }
    return out;
}

[[nodiscard]] std::optional<std::string> validate_macho_uuid_matches_target(
    const peelf::IBinaryImage& dwarf_source_image,
    const peelf::IBinaryImage& target_image,
    std::string_view label) {
    const auto expected_uuid = target_image.macho_uuid();
    const auto actual_uuid = dwarf_source_image.macho_uuid();
    if (!expected_uuid.has_value() || !actual_uuid.has_value()) {
        return std::nullopt;
    }
    if (*expected_uuid == *actual_uuid) {
        return std::nullopt;
    }

    const std::string expected_str = !target_image.macho_uuid_string().empty()
        ? std::string(target_image.macho_uuid_string())
        : format_macho_uuid_canonical(*expected_uuid);
    const std::string actual_str = !dwarf_source_image.macho_uuid_string().empty()
        ? std::string(dwarf_source_image.macho_uuid_string())
        : format_macho_uuid_canonical(*actual_uuid);

    return "Mach-O dSYM LC_UUID does not match target image: " + std::string(label) +
           " (expected UUID=" + expected_str + "; actual UUID=" + actual_str + ")";
}

[[nodiscard]] std::optional<std::filesystem::path> resolve_dsym_bundle_dwarf_file(
    const std::filesystem::path& bundle_dir,
    const peelf::IBinaryImage& target_image) {
    std::error_code ec;
    std::filesystem::path dwarf_dir = bundle_dir / "Contents" / "Resources" / "DWARF";
    if (!std::filesystem::is_directory(dwarf_dir, ec) || ec) {
        ec.clear();
        dwarf_dir = bundle_dir / "Resources" / "DWARF";
        if (!std::filesystem::is_directory(dwarf_dir, ec) || ec) {
            ec.clear();
            if (bundle_dir.filename() == "DWARF" &&
                std::filesystem::is_directory(bundle_dir, ec) && !ec) {
                dwarf_dir = bundle_dir;
            } else {
                return std::nullopt;
            }
        }
    }

    std::string ext = bundle_dir.extension().string();
    std::ranges::transform(ext, ext.begin(), [](unsigned char c) {
        return static_cast<char>(std::tolower(c));
    });
    const std::filesystem::path preferred_name =
        (ext == ".dsym") ? bundle_dir.stem() : std::filesystem::path{};

    std::vector<std::filesystem::path> entries;
    if (!preferred_name.empty()) {
        const std::filesystem::path exact = dwarf_dir / preferred_name;
        std::error_code fec;
        if (std::filesystem::is_regular_file(exact, fec) && !fec) {
            entries.push_back(exact);
        }
    }

    std::vector<std::filesystem::path> others;
    for (const auto& entry : std::filesystem::directory_iterator(dwarf_dir, ec)) {
        if (ec) {
            break;
        }
        std::error_code fec;
        if (!entry.is_regular_file(fec) || fec) {
            continue;
        }
        const std::string fname = entry.path().filename().string();
        if (fname.empty() || fname.front() == '.') {
            continue;
        }
        if (!preferred_name.empty() && entry.path().filename() == preferred_name) {
            continue;
        }
        others.push_back(entry.path());
    }
    std::ranges::sort(others);
    for (auto& p : others) {
        entries.push_back(std::move(p));
    }

    if (entries.empty()) {
        return std::nullopt;
    }
    if (entries.size() == 1u || !target_image.macho_uuid().has_value()) {
        return entries.front();
    }

    for (const auto& cand : entries) {
        std::error_code sz_ec;
        const auto fsz = std::filesystem::file_size(cand, sz_ec);
        if (sz_ec || fsz < 28u || fsz > (512ull * 1024ull * 1024ull)) {
            continue;
        }
        std::ifstream f(cand, std::ios::binary);
        if (!f) {
            continue;
        }
        std::vector<std::uint8_t> buf(static_cast<std::size_t>(fsz));
        if (!f.read(reinterpret_cast<char*>(buf.data()), static_cast<std::streamsize>(buf.size()))) {
            continue;
        }
        peelf::BinaryOpenOptions opts{};
        if (target_image.architecture() != peelf::Architecture::Unknown) {
            opts.preferred_architecture = target_image.architecture();
        }
        if (auto img = peelf::parse_image(buf, opts);
            img.has_value() && (*img)->macho_uuid().has_value() &&
            *(*img)->macho_uuid() == *target_image.macho_uuid()) {
            return cand;
        }
    }

    return entries.front();
}

void sort_and_deduplicate_debug_symbols(std::vector<DebugSymbol>& symbols) {
    std::ranges::sort(symbols, [](const DebugSymbol& lhs, const DebugSymbol& rhs) {
        if (lhs.virtual_address != rhs.virtual_address) {
            return lhs.virtual_address < rhs.virtual_address;
        }
        if (lhs.name != rhs.name) {
            return lhs.name < rhs.name;
        }
        if (lhs.function != rhs.function) {
            return lhs.function > rhs.function;
        }
        if (lhs.size != rhs.size) {
            return lhs.size > rhs.size;
        }
        if (lhs.relative_virtual_address != rhs.relative_virtual_address) {
            return lhs.relative_virtual_address < rhs.relative_virtual_address;
        }
        return lhs.library < rhs.library;
    });
    const auto dup = std::ranges::unique(symbols, [](const DebugSymbol& lhs, const DebugSymbol& rhs) {
        return lhs.virtual_address == rhs.virtual_address && lhs.name == rhs.name;
    });
    symbols.erase(dup.begin(), symbols.end());
}

[[maybe_unused]] [[nodiscard]] std::uint64_t resolve_pe_image_base(
    const peelf::IBinaryImage& image) noexcept {
    if (image.image_base() != 0) {
        return image.image_base();
    }
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

class ScopedDiaModule {
public:
    ScopedDiaModule() noexcept = default;
    explicit ScopedDiaModule(HMODULE mod) noexcept : module_(mod) {}
    ~ScopedDiaModule() noexcept { reset(); }

    ScopedDiaModule(const ScopedDiaModule&) = delete;
    ScopedDiaModule& operator=(const ScopedDiaModule&) = delete;

    ScopedDiaModule(ScopedDiaModule&& other) noexcept
        : module_(std::exchange(other.module_, nullptr)) {}

    ScopedDiaModule& operator=(ScopedDiaModule&& other) noexcept {
        if (this != &other) {
            reset(std::exchange(other.module_, nullptr));
        }
        return *this;
    }

    [[nodiscard]] HMODULE get() const noexcept { return module_; }
    [[nodiscard]] explicit operator bool() const noexcept { return module_ != nullptr; }

    HMODULE release() noexcept { return std::exchange(module_, nullptr); }

    void reset(HMODULE next = nullptr) noexcept {
        if (module_ != nullptr) {
            FreeLibrary(module_);
        }
        module_ = next;
    }

private:
    HMODULE module_{nullptr};
};

class ScopedCoInit {
public:
    explicit ScopedCoInit(bool should_uninitialize) noexcept
        : should_uninitialize_(should_uninitialize) {}

    ~ScopedCoInit() noexcept {
        if (should_uninitialize_) {
            CoUninitialize();
        }
    }

    ScopedCoInit(const ScopedCoInit&) = delete;
    ScopedCoInit& operator=(const ScopedCoInit&) = delete;

private:
    bool should_uninitialize_{false};
};

[[nodiscard]] bool create_dia_source_from_dll(ComPtr<IDiaDataSource>& source,
                                              ScopedDiaModule& module,
                                              std::string& diagnostic) {
#ifdef PEELF_DIA_DLL_PATH
    const std::filesystem::path dll_path(PEELF_DIA_DLL_PATH);
    ScopedDiaModule loaded(LoadLibraryW(dll_path.wstring().c_str()));
    if (!loaded) {
        diagnostic = last_error_message("LoadLibraryW(" + dll_path.string() + ")");
        return false;
    }

    const auto get_class_object =
        reinterpret_cast<DllGetClassObjectFn>(GetProcAddress(loaded.get(), "DllGetClassObject"));
    if (get_class_object == nullptr) {
        diagnostic = last_error_message("GetProcAddress(DllGetClassObject)");
        return false;
    }

    ComPtr<IClassFactory> factory;
    HRESULT hr = get_class_object(__uuidof(DiaSource), __uuidof(IClassFactory),
                                  reinterpret_cast<void**>(factory.put()));
    if (FAILED(hr) || !factory) {
        diagnostic = "DllGetClassObject for DiaSource failed with HRESULT " + format_hresult(hr);
        return false;
    }

    hr = factory->CreateInstance(nullptr, __uuidof(IDiaDataSource), reinterpret_cast<void**>(source.put()));
    if (FAILED(hr) || !source) {
        diagnostic = "DIA class factory CreateInstance failed with HRESULT " + format_hresult(hr);
        return false;
    }

    module = std::move(loaded);
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
                                     ScopedDiaModule& module,
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
        BOOL code = FALSE;
        const bool is_function = function || (SUCCEEDED(symbol->get_code(&code)) && code);
        if (!is_function && length == 0) {
            ComPtr<IDiaSymbol> type;
            if (SUCCEEDED(symbol->get_type(type.put())) && type) type->get_length(&length);
        }

        const auto va = checked_add_rva(image_base, rva);
        if (!va.has_value()) {
            symbol.reset();
            continue;
        }

        out.push_back(DebugSymbol{
            .name = to_utf8(name.get()),
            .relative_virtual_address = rva,
            .virtual_address = *va,
            .size = static_cast<std::uint64_t>(length),
            .function = is_function,
        });
        symbol.reset();
    }
}
std::string dia_type_name(IDiaSymbol& type, unsigned depth = 0) {
    if (depth > 12) return "recursive type";
    Bstr name;
    if (SUCCEEDED(type.get_name(name.put())) && name.get()) return to_utf8(name.get());
    DWORD tag = 0; type.get_symTag(&tag);
    ULONGLONG length = 0; type.get_length(&length);
    if (tag == SymTagPointerType || tag == SymTagArrayType || tag == SymTagTypedef) {
        ComPtr<IDiaSymbol> element;
        if (SUCCEEDED(type.get_type(element.put())) && element) {
            auto text=dia_type_name(*element.get(),depth+1);
            if (tag == SymTagPointerType) return text + "*";
            if (tag == SymTagArrayType) { DWORD count=0; type.get_count(&count); return text+"["+std::to_string(count)+"]"; }
            return text;
        }
    }
    DWORD basic=0; type.get_baseType(&basic);
    switch (basic) {
    case btVoid: return "void";
    case btChar: return "char";
    case btWChar: return "wchar_t";
    case btBool: return "bool";
    case btFloat: return length==4 ? "float" : "double";
    case btInt: case btLong: return "int"+std::to_string(length*8)+"_t";
    case btUInt: case btULong: return "uint"+std::to_string(length*8)+"_t";
    default: return "unknown ("+std::to_string(length)+" bytes)";
    }
}
void add_dia_types(IDiaSymbol& global, std::vector<DataTypeRecord>& out) {
    ComPtr<IDiaEnumSymbols> types;
    if (FAILED(global.findChildren(SymTagUDT,nullptr,nsNone,types.put())) || !types) return;
    ComPtr<IDiaSymbol> type; ULONG fetched=0;
    while (out.size()<10000 && SUCCEEDED(types->Next(1,type.put(),&fetched)) && fetched==1) {
        Bstr name; ULONGLONG size=0; DWORD kind=0;
        type->get_length(&size); type->get_udtKind(&kind);
        if (FAILED(type->get_name(name.put())) || !name.get()) continue;
        DataTypeRecord record{to_utf8(name.get()),size,kind==UdtUnion};
        ComPtr<IDiaEnumSymbols> members;
        if (SUCCEEDED(type->findChildren(SymTagData,nullptr,nsNone,members.put())) && members) {
            ComPtr<IDiaSymbol> member; ULONG count=0;
            while (record.members.size()<4096 && SUCCEEDED(members->Next(1,member.put(),&count)) && count==1) {
                LONG offset=0; DWORD data_kind=0;
                member->get_dataKind(&data_kind);
                if (data_kind != DataIsMember || FAILED(member->get_offset(&offset)) || offset<0) continue;
                Bstr field; ComPtr<IDiaSymbol> field_type; ULONGLONG length=0;
                if (FAILED(member->get_name(field.put())) || !field.get() || FAILED(member->get_type(field_type.put())) || !field_type) continue;
                field_type->get_length(&length);
                auto field_name=dia_type_name(*field_type.get());
                DWORD location=0; member->get_locationType(&location);
                if (location==LocIsBitField) field_name += " (bit field)";
                record.members.push_back({to_utf8(field.get()),std::move(field_name),static_cast<std::uint64_t>(offset),length});
            }
        }
        out.push_back(std::move(record));
    }
    std::ranges::sort(out,{},&DataTypeRecord::name);
    out.erase(std::ranges::unique(out,{},&DataTypeRecord::name).begin(),out.end());
}
#endif

[[nodiscard]] std::vector<SourceLineMapping> convert_pdb_lines(
    std::span<const peelf::PdbLineEntry> pdb_lines,
    std::uint64_t image_base) {
    std::vector<SourceLineMapping> out{};
    out.reserve(pdb_lines.size());
    for (const peelf::PdbLineEntry& entry : pdb_lines) {
        if (entry.relative_address == 0u || entry.line == 0u) {
            continue;
        }
        const auto va = checked_add_rva(image_base, entry.relative_address);
        if (!va.has_value()) {
            continue;
        }
        out.push_back(SourceLineMapping{
            .virtual_address = *va,
            .relative_virtual_address = entry.relative_address,
            .file_path = entry.file_path,
            .file_name = entry.file_name,
            .line = entry.line,
            .column = entry.column,
            .is_stmt = entry.is_stmt,
        });
    }
    std::ranges::sort(out, [](const SourceLineMapping& a, const SourceLineMapping& b) {
        if (a.virtual_address != b.virtual_address) {
            return a.virtual_address < b.virtual_address;
        }
        return a.line < b.line;
    });
    return out;
}

[[nodiscard]] DebugSymbolLoadResult load_pdb_via_peelf_parser(
    const std::filesystem::path& pdb_path,
    const peelf::IBinaryImage& image) {
    const std::uint64_t image_base = resolve_pe_image_base(image);
    auto parsed = peelf::parse_pdb_file(pdb_path, image.sections(), image_base);
    if (!parsed.has_value()) {
        return DebugSymbolLoadResult{
            .status = DebugSymbolLoadStatus::BackendError,
            .diagnostic = parsed.error().message,
        };
    }

    DebugSymbolLoadResult result{};
    result.status = DebugSymbolLoadStatus::Loaded;
    result.diagnostic = pdb_path.string();

    result.symbols.reserve(parsed->symbols.size());
    for (const peelf::PdbSymbol& sym : parsed->symbols) {
        if (sym.relative_address == 0u || sym.name.empty()) {
            continue;
        }
        const auto va = checked_add_rva(image_base, sym.relative_address);
        if (!va.has_value()) {
            continue;
        }
        result.symbols.push_back(DebugSymbol{
            .name = sym.name,
            .relative_virtual_address = sym.relative_address,
            .virtual_address = *va,
            .size = sym.byte_size,
            .function = sym.is_function,
            .library = sym.library_name,
        });
    }
    sort_and_deduplicate_debug_symbols(result.symbols);

    result.types.reserve(parsed->types.size());
    for (const peelf::PdbAggregateType& agg : parsed->types) {
        DataTypeRecord rec{};
        rec.name = agg.name;
        rec.size = agg.byte_size;
        rec.is_union = (agg.kind == peelf::PdbAggregateKind::Union);
        rec.members.reserve(agg.members.size());
        for (const peelf::PdbMemberInfo& m : agg.members) {
            rec.members.push_back(DataMember{
                .name = m.name,
                .type = m.type_name,
                .offset = m.byte_offset,
                .size = m.byte_size,
            });
        }
        result.types.push_back(std::move(rec));
    }
    std::ranges::sort(result.types, [](const DataTypeRecord& a, const DataTypeRecord& b) {
        if (a.name != b.name) {
            return a.name < b.name;
        }
        if (a.members.size() != b.members.size()) {
            return a.members.size() > b.members.size();
        }
        return a.size > b.size;
    });
    const auto dup_types = std::ranges::unique(result.types, {}, &DataTypeRecord::name);
    result.types.erase(dup_types.begin(), dup_types.end());

    result.lines = convert_pdb_lines(parsed->lines, image_base);
    return result;
}

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
        if (pdb_path.is_absolute() && std::filesystem::exists(pdb_path) &&
            pdb_matches_codeview_entry(pdb_path, debug)) {
            return pdb_path;
        }

        const std::string_view raw_cv_path = debug.codeview_pdb_path;
        const std::size_t sep = raw_cv_path.find_last_of("/\\");
        const std::string_view leaf =
            (sep == std::string_view::npos) ? raw_cv_path : raw_cv_path.substr(sep + 1u);
        if (!leaf.empty()) {
            std::filesystem::path sibling = image_path.parent_path() / leaf;
            if (std::filesystem::exists(sibling) &&
                pdb_matches_codeview_entry(sibling, debug)) {
                return sibling;
            }
        }
    }
    return std::nullopt;
}

DebugSymbolLoadResult load_pdb_debug_symbols(const std::filesystem::path& pdb_path,
                                             const peelf::IBinaryImage& image) {
    if (!has_pdb_extension(pdb_path) && !has_native_pdb_signature(pdb_path)) {
        return DebugSymbolLoadResult{
            .status = DebugSymbolLoadStatus::UnsupportedFormat,
            .symbols = {},
            .diagnostic = "Only PDB debug symbol files are supported by this loader",
        };
    }
    if (!std::filesystem::exists(pdb_path)) {
        return DebugSymbolLoadResult{
            .status = DebugSymbolLoadStatus::FileNotFound,
            .symbols = {},
            .diagnostic = pdb_path.string(),
        };
    }
    if (!has_native_pdb_signature(pdb_path)) {
        return DebugSymbolLoadResult{
            .status = DebugSymbolLoadStatus::UnsupportedFormat,
            .symbols = {},
            .diagnostic = "File does not have a recognized native PDB/MSF signature",
        };
    }
    if (const auto mismatch = validate_pdb_matches_image_codeview(pdb_path, image);
        mismatch.has_value()) {
        return DebugSymbolLoadResult{
            .status = DebugSymbolLoadStatus::BackendError,
            .symbols = {},
            .diagnostic = *mismatch,
        };
    }

#if defined(_WIN32) && defined(PEELF_HAS_DIA)
    const HRESULT init_result = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
    const bool should_uninitialize = SUCCEEDED(init_result);
    if (FAILED(init_result) && init_result != RPC_E_CHANGED_MODE) {
        return load_pdb_via_peelf_parser(pdb_path, image);
    }

    // Declare COM and DIA DLL guards strictly BEFORE ComPtr interfaces so
    // reverse-order destruction releases every DIA COM interface prior to
    // FreeLibrary(dia_module) and CoUninitialize().
    const ScopedCoInit com_guard(should_uninitialize);
    ScopedDiaModule dia_module;
    ComPtr<IDiaDataSource> source;
    ComPtr<IDiaSession> session;
    ComPtr<IDiaSymbol> global;

    std::string source_diagnostic;
    if (!create_dia_source(source, dia_module, source_diagnostic)) {
        return load_pdb_via_peelf_parser(pdb_path, image);
    }

    const std::wstring wide_path = to_wstring(pdb_path);
    HRESULT hr = source->loadDataFromPdb(wide_path.c_str());
    if (FAILED(hr)) {
        return load_pdb_via_peelf_parser(pdb_path, image);
    }

    hr = source->openSession(session.put());
    if (FAILED(hr) || !session) {
        return load_pdb_via_peelf_parser(pdb_path, image);
    }

    hr = session->get_globalScope(global.put());
    if (FAILED(hr) || !global) {
        return load_pdb_via_peelf_parser(pdb_path, image);
    }

    const std::uint64_t image_base = resolve_pe_image_base(image);
    DebugSymbolLoadResult result;
    add_dia_children(*global.get(), SymTagFunction, image_base, true, result.symbols);
    add_dia_children(*global.get(), SymTagPublicSymbol, image_base, false, result.symbols);
    add_dia_children(*global.get(), SymTagData, image_base, false, result.symbols);
    add_dia_types(*global.get(), result.types);
    std::map<std::uint64_t,std::string> libraries_by_address;
    {
        ComPtr<IDiaEnumSymbols> compilands;
        if (SUCCEEDED(global->findChildren(SymTagCompiland,nullptr,nsNone,compilands.put())) && compilands) {
            ComPtr<IDiaSymbol> compiland; ULONG fetched=0;
            while (SUCCEEDED(compilands->Next(1,compiland.put(),&fetched)) && fetched==1) {
                Bstr library_name;
                if (FAILED(compiland->get_libraryName(library_name.put())) || !library_name.get()) continue;
                const auto library=to_utf8(library_name.get());
                auto extension=std::filesystem::path(library).extension().string();
                std::ranges::transform(extension,extension.begin(),[](unsigned char c){return static_cast<char>(std::tolower(c));});
                if (extension!=".lib" && extension!=".a") continue;
                std::vector<DebugSymbol> members;
                add_dia_children(*compiland.get(),SymTagFunction,image_base,true,members);
                add_dia_children(*compiland.get(),SymTagData,image_base,false,members);
                for (const auto& member : members) libraries_by_address.try_emplace(member.virtual_address,library);
            }
        }
    }
    for (auto& symbol : result.symbols)
        if (const auto it=libraries_by_address.find(symbol.virtual_address); it!=libraries_by_address.end()) symbol.library=it->second;

    sort_and_deduplicate_debug_symbols(result.symbols);

    if (auto native_pdb = peelf::parse_pdb_file(pdb_path, image.sections(), image_base);
        native_pdb.has_value()) {
        result.lines = convert_pdb_lines(native_pdb->lines, image_base);
    }

    result.status = DebugSymbolLoadStatus::Loaded;
    result.diagnostic = pdb_path.string();
    return result;
#else
    return load_pdb_via_peelf_parser(pdb_path, image);
#endif
}

std::optional<std::filesystem::path> find_local_elf_debug_file(
    const peelf::IBinaryImage& image,
    const std::filesystem::path& image_path,
    std::span<const std::filesystem::path> extra_search_dirs) {
    return peelf::find_separate_debug_file(image_path, image, extra_search_dirs);
}

std::optional<std::filesystem::path> find_local_debug_symbols_file(
    const peelf::IBinaryImage& image,
    const std::filesystem::path& image_path) {
    if (const auto pdb = find_local_codeview_pdb(image, image_path)) {
        return pdb;
    }
    return find_local_elf_debug_file(image, image_path);
}

DebugSymbolLoadResult load_dwarf_debug_symbols_from_image(
    const peelf::IBinaryImage& dwarf_source_image,
    std::span<const std::uint8_t> dwarf_source_bytes,
    const peelf::IBinaryImage& target_image,
    std::string_view diagnostic_label) {
    if (!peelf::has_embedded_dwarf(dwarf_source_image)) {
        return DebugSymbolLoadResult{
            .status = DebugSymbolLoadStatus::UnsupportedFormat,
            .diagnostic = "Image contains neither .debug_info nor .debug_line DWARF sections",
        };
    }

    if (const auto uuid_mismatch = validate_macho_uuid_matches_target(
            dwarf_source_image,
            target_image,
            diagnostic_label.empty() ? std::string_view("DWARF") : diagnostic_label);
        uuid_mismatch.has_value()) {
        return DebugSymbolLoadResult{
            .status = DebugSymbolLoadStatus::BackendError,
            .diagnostic = *uuid_mismatch,
        };
    }

    auto parsed = peelf::parse_dwarf_image(dwarf_source_image, dwarf_source_bytes);
    if (!parsed) {
        return DebugSymbolLoadResult{
            .status = DebugSymbolLoadStatus::BackendError,
            .diagnostic = parsed.error().message,
        };
    }

    std::uint64_t source_base = dwarf_source_image.image_base();
    bool macho_dsym_without_text = false;
    if (dwarf_source_image.format() == peelf::Format::MachO) {
        const bool has_text_seg = std::ranges::any_of(
            dwarf_source_image.macho_segments(),
            [](const peelf::MachOSegmentCommand& s) { return s.name == "__TEXT"; });
        if (!has_text_seg) {
            source_base = 0u;
            macho_dsym_without_text = true;
        }
    }
    const std::uint64_t target_base = target_image.image_base();
    const bool phdr_less_source =
        (source_base == 0u &&
         (dwarf_source_image.segments().empty() || macho_dsym_without_text));

    const auto compute_rva_and_va =
        [&](std::uint64_t raw_addr) noexcept -> std::optional<std::pair<std::uint64_t, std::uint64_t>> {
        std::uint64_t rva = raw_addr;
        if (source_base != 0) {
            rva = (raw_addr >= source_base) ? (raw_addr - source_base) : raw_addr;
        } else if (phdr_less_source && target_base != 0 && raw_addr >= target_base &&
                   target_image.virtual_address_to_file_offset(raw_addr).has_value()) {
            rva = raw_addr - target_base;
        } else if (macho_dsym_without_text && target_image.is_64bit() &&
                   raw_addr >= 0x1'0000'0000ull) {
            const std::uint64_t cand_rva = raw_addr - 0x1'0000'0000ull;
            if (const auto cand_va = checked_add_rva(target_base, cand_rva);
                cand_va.has_value() &&
                target_image.virtual_address_to_file_offset(*cand_va).has_value()) {
                rva = cand_rva;
            }
        }
        if (target_base != 0) {
            const auto va = checked_add_rva(target_base, rva);
            if (!va.has_value()) {
                return std::nullopt;
            }
            return std::pair<std::uint64_t, std::uint64_t>{rva, *va};
        }
        return std::pair<std::uint64_t, std::uint64_t>{rva, raw_addr};
    };

    DebugSymbolLoadResult result;
    result.status = DebugSymbolLoadStatus::Loaded;
    result.diagnostic = diagnostic_label.empty() ? std::string("DWARF") : std::string(diagnostic_label);

    result.symbols.reserve(parsed->functions.size());
    for (const peelf::DwarfFunctionSymbol& fn : parsed->functions) {
        if (fn.low_pc == 0) {
            continue;
        }
        const auto resolved = compute_rva_and_va(fn.low_pc);
        if (!resolved.has_value()) {
            continue;
        }
        const auto [rva, va] = *resolved;
        const std::string& sym_name = !fn.linkage_name.empty() ? fn.linkage_name : fn.name;
        if (sym_name.empty()) {
            continue;
        }
        result.symbols.push_back(DebugSymbol{
            .name = sym_name,
            .relative_virtual_address = rva,
            .virtual_address = va,
            .size = fn.byte_size,
            .function = true,
            .library = fn.comp_unit,
        });
    }
    sort_and_deduplicate_debug_symbols(result.symbols);

    result.types.reserve(parsed->types.size());
    for (const peelf::DwarfAggregateType& agg : parsed->types) {
        DataTypeRecord rec;
        rec.name = agg.name;
        rec.size = agg.byte_size;
        rec.is_union = (agg.kind == peelf::DwarfAggregateKind::Union);
        rec.members.reserve(agg.members.size());
        for (const peelf::DwarfMemberInfo& m : agg.members) {
            rec.members.push_back(DataMember{
                .name = m.name,
                .type = m.type_name,
                .offset = m.byte_offset,
                .size = m.byte_size,
            });
        }
        result.types.push_back(std::move(rec));
    }

    result.lines.reserve(parsed->lines.size());
    for (const peelf::DwarfLineEntry& line : parsed->lines) {
        if (line.address == 0 || line.line == 0) {
            continue;
        }
        const auto resolved = compute_rva_and_va(line.address);
        if (!resolved.has_value()) {
            continue;
        }
        const auto [rva, va] = *resolved;
        result.lines.push_back(SourceLineMapping{
            .virtual_address = va,
            .relative_virtual_address = rva,
            .file_path = line.file_path,
            .file_name = line.file_name,
            .line = line.line,
            .column = line.column,
            .is_stmt = line.is_stmt,
        });
    }

    std::ranges::sort(result.lines, [](const SourceLineMapping& a, const SourceLineMapping& b) {
        if (a.virtual_address != b.virtual_address) {
            return a.virtual_address < b.virtual_address;
        }
        return a.line < b.line;
    });

    return result;
}

DebugSymbolLoadResult load_dwarf_debug_symbols(const std::filesystem::path& debug_path,
                                               const peelf::IBinaryImage& target_image) {
    std::error_code ec;
    if (!std::filesystem::exists(debug_path, ec)) {
        return DebugSymbolLoadResult{
            .status = DebugSymbolLoadStatus::FileNotFound,
            .diagnostic = debug_path.string(),
        };
    }

    std::filesystem::path effective_path = debug_path;
    if (std::filesystem::is_directory(debug_path, ec) && !ec) {
        const auto resolved = resolve_dsym_bundle_dwarf_file(debug_path, target_image);
        if (!resolved.has_value()) {
            return DebugSymbolLoadResult{
                .status = DebugSymbolLoadStatus::FileNotFound,
                .diagnostic = "No DWARF companion file found inside .dSYM bundle: " +
                              debug_path.string(),
            };
        }
        effective_path = *resolved;
    }

    constexpr std::uintmax_t kMaxDwarfFileSize = 512ull * 1024ull * 1024ull;
    const auto fsize = std::filesystem::file_size(effective_path, ec);
    if (ec || fsize < 16u || fsize > kMaxDwarfFileSize) {
        return DebugSymbolLoadResult{
            .status = DebugSymbolLoadStatus::BackendError,
            .diagnostic = "Unable to read DWARF file size: " + effective_path.string(),
        };
    }

    std::ifstream file(effective_path, std::ios::binary);
    if (!file) {
        return DebugSymbolLoadResult{
            .status = DebugSymbolLoadStatus::FileNotFound,
            .diagnostic = effective_path.string(),
        };
    }

    std::vector<std::uint8_t> bytes(static_cast<std::size_t>(fsize));
    if (!file.read(reinterpret_cast<char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()))) {
        return DebugSymbolLoadResult{
            .status = DebugSymbolLoadStatus::BackendError,
            .diagnostic = "Failed reading DWARF file: " + effective_path.string(),
        };
    }

    peelf::BinaryOpenOptions open_opts{};
    if (target_image.architecture() != peelf::Architecture::Unknown) {
        open_opts.preferred_architecture = target_image.architecture();
    }
    auto parsed_image = peelf::parse_image(bytes, open_opts);
    if (!parsed_image && open_opts.preferred_architecture.has_value()) {
        parsed_image = peelf::parse_image(bytes);
    }
    if (!parsed_image) {
        return DebugSymbolLoadResult{
            .status = DebugSymbolLoadStatus::UnsupportedFormat,
            .diagnostic = parsed_image.error().message,
        };
    }

    return load_dwarf_debug_symbols_from_image(
        **parsed_image, bytes, target_image, effective_path.string());
}

DebugSymbolLoadResult load_debug_symbols_file(const std::filesystem::path& debug_path,
                                              const peelf::IBinaryImage& target_image) {
    std::error_code ec;
    if (!std::filesystem::exists(debug_path, ec)) {
        return DebugSymbolLoadResult{
            .status = DebugSymbolLoadStatus::FileNotFound,
            .diagnostic = debug_path.string(),
        };
    }
    if (std::filesystem::is_directory(debug_path, ec) && !ec) {
        return load_dwarf_debug_symbols(debug_path, target_image);
    }
    if (has_pdb_extension(debug_path) || has_native_pdb_signature(debug_path)) {
        return load_pdb_debug_symbols(debug_path, target_image);
    }
    return load_dwarf_debug_symbols(debug_path, target_image);
}

std::vector<DebugSymbol> rebase_debug_symbols(std::span<const DebugSymbol> symbols,
                                              std::uint64_t image_base) {
    std::vector<DebugSymbol> rebased;
    rebased.reserve(symbols.size());
    for (DebugSymbol sym : symbols) {
        if (sym.relative_virtual_address != 0) {
            const auto va = checked_add_rva(image_base, sym.relative_virtual_address);
            if (!va.has_value()) {
                continue;
            }
            sym.virtual_address = *va;
        }
        rebased.push_back(std::move(sym));
    }
    return rebased;
}

std::vector<SourceLineMapping> rebase_source_lines(std::span<const SourceLineMapping> lines,
                                                   std::uint64_t image_base) {
    std::vector<SourceLineMapping> rebased;
    rebased.reserve(lines.size());
    for (SourceLineMapping entry : lines) {
        if (entry.relative_virtual_address != 0) {
            const auto va = checked_add_rva(image_base, entry.relative_virtual_address);
            if (!va.has_value()) {
                continue;
            }
            entry.virtual_address = *va;
        }
        rebased.push_back(std::move(entry));
    }
    std::ranges::sort(rebased, [](const SourceLineMapping& a, const SourceLineMapping& b) {
        if (a.virtual_address != b.virtual_address) {
            return a.virtual_address < b.virtual_address;
        }
        return a.line < b.line;
    });
    return rebased;
}

} // namespace viewer
