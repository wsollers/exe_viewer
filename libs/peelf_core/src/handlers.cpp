#include <peelf/handlers.hpp>

#include <algorithm>
#include <array>
#include <bit>
#include <cctype>
#include <charconv>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <limits>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

namespace peelf {

namespace {

// ---------------------------------------------------------------------------
// Small formatting & string utilities (no <format> dependency for libstdc++12)
// ---------------------------------------------------------------------------

[[nodiscard]] std::string hex_u64(std::uint64_t value, std::size_t min_digits = 0) {
    std::array<char, 24> buf{};
    auto [ptr, ec] = std::to_chars(buf.data(), buf.data() + buf.size(), value, 16);
    if (ec != std::errc{}) {
        return "0x0";
    }
    const auto digits_len = static_cast<std::size_t>(ptr - buf.data());
    std::string out = "0x";
    if (min_digits > digits_len) {
        out.append(min_digits - digits_len, '0');
    }
    out.append(buf.data(), digits_len);
    return out;
}

[[nodiscard]] std::string_view trim_ascii(std::string_view s) noexcept {
    while (!s.empty() &&
           (s.front() == ' ' || s.front() == '\t' || s.front() == '\r' || s.front() == '\n')) {
        s.remove_prefix(1);
    }
    while (!s.empty() &&
           (s.back() == ' ' || s.back() == '\t' || s.back() == '\r' || s.back() == '\n')) {
        s.remove_suffix(1);
    }
    return s;
}

[[nodiscard]] bool iequals_ascii(std::string_view a, std::string_view b) noexcept {
    if (a.size() != b.size()) {
        return false;
    }
    for (std::size_t i = 0; i < a.size(); ++i) {
        if (std::tolower(static_cast<unsigned char>(a[i])) !=
            std::tolower(static_cast<unsigned char>(b[i]))) {
            return false;
        }
    }
    return true;
}

[[nodiscard]] bool icontains_ascii(std::string_view haystack, std::string_view needle) noexcept {
    if (needle.empty()) {
        return true;
    }
    if (haystack.size() < needle.size()) {
        return false;
    }
    const std::size_t limit = haystack.size() - needle.size();
    for (std::size_t i = 0; i <= limit; ++i) {
        if (iequals_ascii(haystack.substr(i, needle.size()), needle)) {
            return true;
        }
    }
    return false;
}

[[nodiscard]] std::optional<std::uint64_t> parse_hex_u64(std::string_view token) noexcept {
    token = trim_ascii(token);
    if (token.starts_with("0x") || token.starts_with("0X")) {
        token.remove_prefix(2);
    }
    if (token.empty()) {
        return std::nullopt;
    }
    std::uint64_t value = 0;
    const auto [ptr, ec] = std::from_chars(token.data(), token.data() + token.size(), value, 16);
    if (ec != std::errc{} || ptr != token.data() + token.size()) {
        return std::nullopt;
    }
    return value;
}

[[nodiscard]] std::optional<std::uint64_t> checked_add_u64(std::uint64_t a,
                                                           std::uint64_t b) noexcept {
    if (b > std::numeric_limits<std::uint64_t>::max() - a) {
        return std::nullopt;
    }
    return a + b;
}

[[nodiscard]] std::string_view strip_symbol_decorations(std::string_view raw) noexcept {
    const auto bang = raw.rfind('!');
    if (bang != std::string_view::npos) {
        raw.remove_prefix(bang + 1);
    }
    if (raw.starts_with("__imp_")) {
        raw.remove_prefix(6);
    } else if (raw.starts_with("_imp__")) {
        raw.remove_prefix(6);
    }
    const auto ver_at = raw.find('@');
    if (ver_at != std::string_view::npos && ver_at > 0) {
        // Strip either ELF "@@GLIBC_..." / "@GLIBC_..." or Win32 stdcall "@8".
        raw = raw.substr(0, ver_at);
    }
    return raw;
}

[[nodiscard]] bool symbol_matches_identifier(std::string_view raw,
                                             std::string_view expected) noexcept {
    const std::string_view clean = strip_symbol_decorations(raw);
    if (clean == expected) {
        return true;
    }
    // 32-bit x86 COFF / cdecl leading underscore (e.g. _SetUnhandledExceptionFilter -> SetUnhandledExceptionFilter).
    if (!clean.empty() && clean.front() == '_' && clean.substr(1) == expected) {
        return true;
    }
    return false;
}

[[nodiscard]] HandlerEntry make_entry(HandlerCategory cat,
                                      std::string name,
                                      std::uint64_t handler_address,
                                      std::string symbol_name,
                                      std::string detail) {
    HandlerEntry e;
    e.category = cat;
    e.category_label = std::string(to_string(cat));
    e.name = std::move(name);
    e.handler_address = handler_address;
    e.symbol_name = std::move(symbol_name);
    e.detail = std::move(detail);
    return e;
}

[[nodiscard]] std::optional<std::vector<std::uint8_t>> read_disk_file_readonly(
    const std::filesystem::path& path) {
    if (path.empty()) {
        return std::nullopt;
    }
    std::error_code ec;
    if (!std::filesystem::is_regular_file(path, ec) || ec) {
        return std::nullopt;
    }
    const auto fsize = std::filesystem::file_size(path, ec);
    constexpr std::uintmax_t kMaxDebugFile = 128ull * 1024ull * 1024ull;
    if (ec || fsize == 0 || fsize > kMaxDebugFile) {
        return std::nullopt;
    }
    std::ifstream ifs(path, std::ios::binary);
    if (!ifs) {
        return std::nullopt;
    }
    std::vector<std::uint8_t> bytes(static_cast<std::size_t>(fsize));
    ifs.read(reinterpret_cast<char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
    if (!ifs) {
        return std::nullopt;
    }
    return bytes;
}

// ---------------------------------------------------------------------------
// Unified byte-reading, module-caching, and symbol-resolution context
// ---------------------------------------------------------------------------

struct PeModuleSafeSehInfo {
    bool is_pe{false};
    bool no_seh{false};
    bool has_safeseh_table{false};
    std::unordered_set<std::uint64_t> safe_handlers;
};

class HandlerInspectorContext {
public:
    HandlerInspectorContext(const IBinaryImage* image,
                            std::span<const std::uint8_t> static_or_module_bytes,
                            IProcessSession* session,
                            std::span<const MemoryRegion> regions,
                            std::span<const ModuleInfo> modules,
                            const ThreadContext* selected_thread,
                            std::function<std::string(std::uint64_t)> symbol_resolver,
                            TargetLayout layout)
        : image_(image),
          static_bytes_(static_or_module_bytes),
          session_(session),
          regions_(regions),
          modules_(modules),
          selected_thread_(selected_thread),
          symbol_resolver_(std::move(symbol_resolver)),
          layout_(layout) {}

    [[nodiscard]] const IBinaryImage* image() const noexcept { return image_; }
    [[nodiscard]] std::span<const std::uint8_t> static_bytes() const noexcept { return static_bytes_; }
    [[nodiscard]] IProcessSession* session() const noexcept { return session_; }
    [[nodiscard]] std::span<const MemoryRegion> regions() const noexcept { return regions_; }
    [[nodiscard]] std::span<const ModuleInfo> modules() const noexcept { return modules_; }
    [[nodiscard]] const ThreadContext* selected_thread() const noexcept { return selected_thread_; }
    [[nodiscard]] TargetLayout layout() const noexcept { return layout_; }

    [[nodiscard]] static std::optional<std::uint64_t> image_va_to_offset(const IBinaryImage& img,
                                                                         std::uint64_t va) noexcept {
        if (auto off = img.virtual_address_to_file_offset(va)) {
            return off;
        }
        // Fallback for section-only or relocatable images without PT_LOAD program headers.
        for (const Section& sec : img.sections()) {
            if (sec.file_size == 0) {
                continue;
            }
            if (img.format() == Format::ELF && !sec.readable && !sec.writable && !sec.executable &&
                sec.virtual_address == 0) {
                continue;
            }
            if (va >= sec.virtual_address && (va - sec.virtual_address) < sec.file_size) {
                return checked_add_u64(sec.file_offset, va - sec.virtual_address);
            }
        }
        return std::nullopt;
    }

    /// Read `[va, va + size)` from `static_or_module_bytes` (via `image->virtual_address_to_file_offset`)
    /// when available, falling back to `session->read_memory(va, ...)` when attached to a live process.
    [[nodiscard]] std::optional<std::vector<std::uint8_t>> read_va(
        std::uint64_t va,
        std::size_t size,
        bool prefer_live = false) {
        if (size == 0) {
            return std::vector<std::uint8_t>{};
        }
        if (prefer_live) {
            if (auto live = read_live_va(va, size)) {
                return live;
            }
            return read_static_va(va, size);
        }
        if (auto st = read_static_va(va, size)) {
            return st;
        }
        return read_live_va(va, size);
    }

    [[nodiscard]] std::optional<std::vector<std::uint8_t>> read_static_va(
        std::uint64_t va,
        std::size_t size) const {
        if (image_ == nullptr || static_bytes_.empty() || size == 0) {
            return std::nullopt;
        }
        const auto off = image_va_to_offset(*image_, va);
        if (!off || *off > static_bytes_.size()) {
            return std::nullopt;
        }
        const auto start = static_cast<std::size_t>(*off);
        if (size > static_bytes_.size() - start) {
            return std::nullopt;
        }
        return std::vector<std::uint8_t>(static_bytes_.begin() + static_cast<std::ptrdiff_t>(start),
                                         static_bytes_.begin() +
                                             static_cast<std::ptrdiff_t>(start + size));
    }

    [[nodiscard]] std::optional<std::vector<std::uint8_t>> read_live_va(std::uint64_t va,
                                                                        std::size_t size) {
        if (session_ == nullptr || size == 0) {
            return std::nullopt;
        }
        std::vector<std::uint8_t> buf(size, 0);
        auto direct = session_->read_memory(va, buf);
        if (direct && *direct == size) {
            return buf;
        }
        MemorySample sample = read_memory_tolerant(*session_, regions_, va, size);
        if (sample.readable_count == size) {
            return std::move(sample.bytes);
        }
        return std::nullopt;
    }

    [[nodiscard]] const IBinaryImage* get_or_load_module_image(const ModuleInfo& mod) {
        if (session_ == nullptr || (mod.base_address == 0 && mod.size == 0)) {
            return nullptr;
        }
        if (image_ != nullptr && image_->image_base() == mod.base_address) {
            return image_;
        }
        auto it = module_images_.find(mod.base_address);
        if (it != module_images_.end()) {
            return it->second.get();
        }
        auto loaded = load_live_module_image(*session_, mod, regions_);
        if (!loaded) {
            module_images_.emplace(mod.base_address, nullptr);
            return nullptr;
        }
        const IBinaryImage* ptr = loaded->get();
        module_images_.emplace(mod.base_address, std::move(*loaded));
        return ptr;
    }

    [[nodiscard]] const IBinaryImage* get_or_load_build_id_debug_image(
        const IBinaryImage& runtime_img) {
        const std::uint64_t key = runtime_img.image_base();
        auto it = debug_images_.find(key);
        if (it != debug_images_.end()) {
            return it->second.get();
        }

        std::unique_ptr<IBinaryImage> parsed_dbg;
        for (const ElfNote& note : runtime_img.elf_notes()) {
            if (note.name != "GNU" || note.type != 3u || note.descriptor.size() < 2u) {
                continue;
            }
            static constexpr char kHex[] = "0123456789abcdef";
            std::string dir_hex;
            dir_hex.push_back(kHex[(note.descriptor[0] >> 4) & 0x0Fu]);
            dir_hex.push_back(kHex[note.descriptor[0] & 0x0Fu]);

            std::string file_hex;
            file_hex.reserve((note.descriptor.size() - 1u) * 2u);
            for (std::size_t i = 1; i < note.descriptor.size(); ++i) {
                file_hex.push_back(kHex[(note.descriptor[i] >> 4) & 0x0Fu]);
                file_hex.push_back(kHex[note.descriptor[i] & 0x0Fu]);
            }
            const std::filesystem::path dbg_path =
                std::filesystem::path("/usr/lib/debug/.build-id") / dir_hex / (file_hex + ".debug");
            if (auto bytes = read_disk_file_readonly(dbg_path)) {
                auto rebased = parse_rebased_image(*bytes, runtime_img.image_base());
                if (rebased) {
                    parsed_dbg = std::move(*rebased);
                    break;
                }
            }
        }
        const IBinaryImage* raw = parsed_dbg.get();
        debug_images_.emplace(key, std::move(parsed_dbg));
        return raw;
    }

    [[nodiscard]] std::optional<bool> is_executable_address(std::uint64_t va) const noexcept {
        if (va == 0) {
            return false;
        }
        for (const MemoryRegion& reg : regions_) {
            if (reg.contains(va)) {
                return reg.protection.executable;
            }
        }
        if (image_ != nullptr) {
            for (const Section& sec : image_->sections()) {
                const std::uint64_t span = std::max(sec.virtual_size, sec.file_size);
                if (span > 0 && va >= sec.virtual_address && (va - sec.virtual_address) < span) {
                    return sec.executable;
                }
            }
            for (const Segment& seg : image_->segments()) {
                if (seg.type != 1u) {
                    continue;
                }
                const std::uint64_t span = std::max(seg.virtual_size, seg.file_size);
                if (span > 0 && va >= seg.virtual_address && (va - seg.virtual_address) < span) {
                    return seg.executable;
                }
            }
        }
        if (!regions_.empty()) {
            return false;
        }
        return std::nullopt;
    }

    [[nodiscard]] bool image_contains_va(const IBinaryImage& img, std::uint64_t va) const noexcept {
        if (const PeHeader* pe = img.pe_header()) {
            if (pe->size_of_image > 0 && va >= img.image_base() &&
                (va - img.image_base()) < static_cast<std::uint64_t>(pe->size_of_image)) {
                return true;
            }
        }
        for (const Section& sec : img.sections()) {
            const std::uint64_t span = std::max(sec.virtual_size, sec.file_size);
            if (span > 0 && va >= sec.virtual_address && (va - sec.virtual_address) < span) {
                return true;
            }
        }
        for (const Segment& seg : img.segments()) {
            if (seg.type != 1u) {
                continue;
            }
            const std::uint64_t span = std::max(seg.virtual_size, seg.file_size);
            if (span > 0 && va >= seg.virtual_address && (va - seg.virtual_address) < span) {
                return true;
            }
        }
        return false;
    }

    [[nodiscard]] std::string lookup_symbol_in_image(const IBinaryImage& img,
                                                     std::uint64_t va,
                                                     std::string_view module_prefix = {}) const {
        const auto with_prefix = [&](const std::string& sym) -> std::string {
            if (module_prefix.empty()) {
                return sym;
            }
            return std::string(module_prefix) + "!" + sym;
        };

        const bool arm_thumb = (layout_.architecture == Architecture::ARM);
        const std::uint64_t norm_va = arm_thumb ? (va & ~std::uint64_t{1}) : va;

        for (const Symbol& sym : img.symbols()) {
            if (sym.name.empty() || sym.virtual_address == 0) {
                continue;
            }
            const std::uint64_t sym_va =
                arm_thumb ? (sym.virtual_address & ~std::uint64_t{1}) : sym.virtual_address;
            if (sym_va == norm_va) {
                return with_prefix(sym.name);
            }
        }
        for (const ExportEntry& exp : img.exports()) {
            if (exp.virtual_address == 0) {
                continue;
            }
            const std::uint64_t exp_va =
                arm_thumb ? (exp.virtual_address & ~std::uint64_t{1}) : exp.virtual_address;
            if (exp_va == norm_va) {
                if (!exp.name.empty()) {
                    return with_prefix(exp.name);
                }
                return with_prefix("ordinal_" + std::to_string(exp.ordinal));
            }
        }
        for (const ImportEntry& imp : img.imports()) {
            if (imp.address != 0 && imp.address == va) {
                const std::string base =
                    !imp.name.empty() ? imp.name : ("ordinal_" + std::to_string(imp.ordinal));
                if (!imp.library.empty()) {
                    return imp.library + "!" + base;
                }
                return with_prefix(base);
            }
        }
        for (const Symbol& sym : img.symbols()) {
            if (sym.name.empty() || sym.virtual_address == 0 || sym.size == 0) {
                continue;
            }
            const std::uint64_t sym_va =
                arm_thumb ? (sym.virtual_address & ~std::uint64_t{1}) : sym.virtual_address;
            if (norm_va > sym_va && (norm_va - sym_va) < sym.size) {
                return with_prefix(sym.name + "+" + hex_u64(norm_va - sym_va));
            }
        }
        return {};
    }

    [[nodiscard]] std::string resolve_symbol(std::uint64_t va) {
        if (va == 0) {
            return {};
        }
        if (symbol_resolver_) {
            std::string resolved = symbol_resolver_(va);
            if (!resolved.empty()) {
                return resolved;
            }
        }
        if (image_ != nullptr) {
            std::string sym = lookup_symbol_in_image(*image_, va);
            if (!sym.empty()) {
                return sym;
            }
        }
        for (const ModuleInfo& mod : modules_) {
            if (mod.contains(va)) {
                auto it = module_images_.find(mod.base_address);
                if (it != module_images_.end() && it->second != nullptr) {
                    std::string msym = lookup_symbol_in_image(*it->second, va, mod.name);
                    if (!msym.empty()) {
                        return msym;
                    }
                }
                const std::string mod_label =
                    !mod.name.empty() ? mod.name : mod.path.filename().string();
                if (!mod_label.empty()) {
                    return mod_label + "+" + hex_u64(va - mod.base_address);
                }
            }
        }
        for (const MemoryRegion& reg : regions_) {
            if (reg.contains(va) && !reg.module_name.empty()) {
                return reg.module_name + "+" + hex_u64(va - reg.start_address);
            }
        }
        if (image_ != nullptr && image_contains_va(*image_, va) && va >= image_->image_base()) {
            return "image+" + hex_u64(va - image_->image_base());
        }
        return {};
    }

private:
    const IBinaryImage* image_{nullptr};
    std::span<const std::uint8_t> static_bytes_;
    IProcessSession* session_{nullptr};
    std::span<const MemoryRegion> regions_;
    std::span<const ModuleInfo> modules_;
    const ThreadContext* selected_thread_{nullptr};
    std::function<std::string(std::uint64_t)> symbol_resolver_;
    TargetLayout layout_{};
    std::unordered_map<std::uint64_t, std::unique_ptr<IBinaryImage>> module_images_;
    std::unordered_map<std::uint64_t, std::unique_ptr<IBinaryImage>> debug_images_;
};

// ---------------------------------------------------------------------------
// PE Static, Unwind, SafeSEH, GuardEH, CRT, TLS, and Live SEH/VEH/VCH
// ---------------------------------------------------------------------------

[[nodiscard]] PeModuleSafeSehInfo extract_pe_safeseh_for_image(
    const IBinaryImage& img,
    HandlerInspectorContext& ctx,
    bool is_primary_image,
    std::vector<HandlerEntry>* emit_entries,
    bool& had_read_failure) {
    PeModuleSafeSehInfo info;
    if (img.format() != Format::PE) {
        return info;
    }
    info.is_pe = true;
    if (const PeHeader* hdr = img.pe_header()) {
        constexpr std::uint16_t kDllCharNoSeh = 0x0400u;
        info.no_seh = (hdr->dll_characteristics & kDllCharNoSeh) != 0;
    }

    const PeLoadConfigDirectory* lc = img.pe_load_config_directory();
    if (lc == nullptr || lc->se_handler_table == 0 || lc->se_handler_count == 0) {
        return info;
    }

    info.has_safeseh_table = true;
    const std::uint64_t table_va =
        (lc->se_handler_table < img.image_base())
            ? (img.image_base() + lc->se_handler_table)
            : lc->se_handler_table;

    constexpr std::uint64_t kMaxSafeSehEntries = 4096;
    const auto count = static_cast<std::size_t>(std::min(lc->se_handler_count, kMaxSafeSehEntries));
    const std::size_t byte_len = count * 4u;

    std::optional<std::vector<std::uint8_t>> buf =
        is_primary_image ? ctx.read_va(table_va, byte_len) : ctx.read_live_va(table_va, byte_len);
    if (!buf) {
        had_read_failure = true;
        return info;
    }

    const EndianReader reader(*buf, TargetLayout::from_image(img));
    for (std::size_t i = 0; i < count; ++i) {
        const auto rva = reader.read_u32(i * 4u);
        if (!rva) {
            break;
        }
        if (*rva == 0) {
            continue;
        }
        const std::uint64_t handler_va = img.image_base() + static_cast<std::uint64_t>(*rva);
        info.safe_handlers.insert(handler_va);
        if (emit_entries != nullptr) {
            std::string det = "LoadConfig SEHandlerTable RVA " + hex_u64(*rva);
            if (lc->se_handler_count > kMaxSafeSehEntries && i + 1 == count) {
                det += " (capped at 4096 entries)";
            }
            HandlerEntry e = make_entry(HandlerCategory::SafeSehTable,
                                        "SafeSEH[" + std::to_string(i) + "]",
                                        handler_va,
                                        ctx.resolve_symbol(handler_va),
                                        std::move(det));
            e.record_address = table_va + static_cast<std::uint64_t>(i * 4u);
            e.validated_safe = true;
            emit_entries->push_back(std::move(e));
        }
    }
    return info;
}

void inspect_pe_static_and_unwind(HandlerInspectorContext& ctx,
                                  HandlersReport& report,
                                  PeModuleSafeSehInfo& primary_safeseh) {
    const IBinaryImage* image = ctx.image();
    if (image == nullptr) {
        report.static_handlers_status =
            SubsystemStatus::unavailable("pe-headers", "no PE image available");
        report.unwind_handlers_status =
            SubsystemStatus::unavailable("pe-pdata", "no PE image available");
        return;
    }

    const TargetLayout layout = ctx.layout();
    const std::size_t ptr_size = layout.pointer_size();
    bool static_partial = false;

    // 1. TLS Callbacks (static directory + live re-read if attached)
    if (const PeTlsDirectory* tls = image->pe_tls_directory()) {
        std::vector<std::uint64_t> live_callbacks;
        bool have_live_callbacks = false;
        if (ctx.session() != nullptr && tls->address_of_callbacks != 0) {
            constexpr std::size_t kMaxTlsCallbacks = 256;
            for (std::size_t idx = 0; idx < kMaxTlsCallbacks; ++idx) {
                const std::uint64_t slot_va =
                    tls->address_of_callbacks + static_cast<std::uint64_t>(idx * ptr_size);
                auto slot_bytes = ctx.read_live_va(slot_va, ptr_size);
                if (!slot_bytes) {
                    if (idx == 0) {
                        static_partial = true;
                    }
                    break;
                }
                have_live_callbacks = true;
                const EndianReader er(*slot_bytes, layout);
                const auto cb = er.read_pointer(0);
                if (!cb || *cb == 0) {
                    break;
                }
                live_callbacks.push_back(*cb);
            }
        }

        if (have_live_callbacks) {
            const std::size_t max_len = std::max(tls->callbacks.size(), live_callbacks.size());
            for (std::size_t idx = 0; idx < max_len; ++idx) {
                const std::uint64_t slot_va =
                    tls->address_of_callbacks + static_cast<std::uint64_t>(idx * ptr_size);
                const bool has_static = idx < tls->callbacks.size();
                const bool has_live = idx < live_callbacks.size();
                if (has_live) {
                    const std::uint64_t cb_va = live_callbacks[idx];
                    std::string detail = "PE TLS callback";
                    if (!has_static) {
                        detail += " (dynamically appended in live memory)";
                    } else if (tls->callbacks[idx] != cb_va) {
                        detail += " (modified in live memory; static=" +
                                  hex_u64(tls->callbacks[idx]) + ")";
                    } else {
                        detail += " (verified in live memory)";
                    }
                    HandlerEntry e = make_entry(HandlerCategory::TlsCallback,
                                                "TLS Callback[" + std::to_string(idx) + "]",
                                                cb_va,
                                                ctx.resolve_symbol(cb_va),
                                                std::move(detail));
                    e.record_address = slot_va;
                    if (auto exec = ctx.is_executable_address(cb_va)) {
                        e.validated_safe = *exec;
                    }
                    report.entries.push_back(std::move(e));
                } else if (has_static) {
                    const std::uint64_t cb_va = tls->callbacks[idx];
                    HandlerEntry e = make_entry(
                        HandlerCategory::TlsCallback,
                        "TLS Callback[" + std::to_string(idx) + "]",
                        cb_va,
                        ctx.resolve_symbol(cb_va),
                        "PE TLS callback (static header; cleared to NULL in live memory)");
                    e.record_address = slot_va;
                    report.entries.push_back(std::move(e));
                }
            }
        } else if (!tls->callbacks.empty()) {
            for (std::size_t idx = 0; idx < tls->callbacks.size(); ++idx) {
                const std::uint64_t cb_va = tls->callbacks[idx];
                HandlerEntry e = make_entry(HandlerCategory::TlsCallback,
                                            "TLS Callback[" + std::to_string(idx) + "]",
                                            cb_va,
                                            ctx.resolve_symbol(cb_va),
                                            "PE IMAGE_TLS_DIRECTORY AddressOfCallBacks");
                if (tls->address_of_callbacks != 0) {
                    e.record_address =
                        tls->address_of_callbacks + static_cast<std::uint64_t>(idx * ptr_size);
                }
                if (auto exec = ctx.is_executable_address(cb_va)) {
                    e.validated_safe = *exec;
                }
                report.entries.push_back(std::move(e));
            }
        } else if (tls->address_of_callbacks != 0) {
            constexpr std::size_t kMaxStaticTlsCallbacks = 256;
            for (std::size_t idx = 0; idx < kMaxStaticTlsCallbacks; ++idx) {
                const std::uint64_t slot_va =
                    tls->address_of_callbacks + static_cast<std::uint64_t>(idx * ptr_size);
                auto slot_bytes = ctx.read_va(slot_va, ptr_size);
                if (!slot_bytes) {
                    if (idx == 0) {
                        static_partial = true;
                    }
                    break;
                }
                const EndianReader er(*slot_bytes, layout);
                const auto cb = er.read_pointer(0);
                if (!cb || *cb == 0) {
                    break;
                }
                HandlerEntry e = make_entry(HandlerCategory::TlsCallback,
                                            "TLS Callback[" + std::to_string(idx) + "]",
                                            *cb,
                                            ctx.resolve_symbol(*cb),
                                            "PE IMAGE_TLS_DIRECTORY AddressOfCallBacks");
                e.record_address = slot_va;
                if (auto exec = ctx.is_executable_address(*cb)) {
                    e.validated_safe = *exec;
                }
                report.entries.push_back(std::move(e));
            }
        }
    }

    // 2. CRT Init / Exit Tables (.CRT$XI*, .CRT$XC*, .CRT$XP*, .CRT$XT* & __xi/__xc/__xp/__xt)
    std::unordered_set<std::uint64_t> seen_crt_slots;
    const auto describe_crt_prefix = [](std::string_view tag) -> std::string_view {
        if (icontains_ascii(tag, "XI")) {
            return "CRT C initializer table";
        }
        if (icontains_ascii(tag, "XC")) {
            return "CRT C++ dynamic initializer table";
        }
        if (icontains_ascii(tag, "XP")) {
            return "CRT pre-terminator table";
        }
        if (icontains_ascii(tag, "XT")) {
            return "CRT terminator table";
        }
        return "CRT initializer/terminator table";
    };

    const auto scan_crt_range = [&](std::uint64_t start_va,
                                    std::uint64_t byte_span,
                                    std::string_view label_prefix) {
        if (start_va == 0 || byte_span < ptr_size) {
            return;
        }
        constexpr std::size_t kMaxCrtEntries = 2048;
        const std::size_t max_bytes = kMaxCrtEntries * ptr_size;
        const auto clamped_bytes = static_cast<std::size_t>(
            std::min<std::uint64_t>(byte_span, static_cast<std::uint64_t>(max_bytes)));
        const std::size_t aligned_bytes = (clamped_bytes / ptr_size) * ptr_size;
        if (aligned_bytes == 0) {
            return;
        }
        auto buf = ctx.read_va(start_va, aligned_bytes);
        if (!buf) {
            static_partial = true;
            return;
        }
        const EndianReader reader(*buf, layout);
        const std::size_t slots = aligned_bytes / ptr_size;
        std::size_t emitted_idx = 0;
        for (std::size_t i = 0; i < slots; ++i) {
            const auto fn = reader.read_pointer(i * ptr_size);
            if (!fn || *fn == 0) {
                continue;
            }
            const std::uint64_t slot_va = start_va + static_cast<std::uint64_t>(i * ptr_size);
            if (!seen_crt_slots.insert(slot_va).second) {
                continue;
            }
            HandlerEntry e = make_entry(
                HandlerCategory::CrtInitializer,
                std::string(label_prefix) + "[" + std::to_string(emitted_idx++) + "]",
                *fn,
                ctx.resolve_symbol(*fn),
                std::string(describe_crt_prefix(label_prefix)));
            e.record_address = slot_va;
            if (auto exec = ctx.is_executable_address(*fn)) {
                e.validated_safe = *exec;
            }
            report.entries.push_back(std::move(e));
        }
    };

    for (const Section& sec : image->sections()) {
        if (sec.name.starts_with(".CRT$XI") || sec.name.starts_with(".CRT$XC") ||
            sec.name.starts_with(".CRT$XP") || sec.name.starts_with(".CRT$XT")) {
            const std::uint64_t span =
                sec.file_size != 0 ? std::min(sec.virtual_size != 0 ? sec.virtual_size : sec.file_size,
                                              sec.file_size)
                                   : sec.virtual_size;
            scan_crt_range(sec.virtual_address, span, sec.name);
        }
    }

    struct CrtSymRange {
        std::string_view start_sym;
        std::string_view end_sym;
        std::string_view label;
    };
    static constexpr std::array<CrtSymRange, 4> kCrtSymRanges{{
        {"__xi_a", "__xi_z", ".CRT$XI"},
        {"__xc_a", "__xc_z", ".CRT$XC"},
        {"__xp_a", "__xp_z", ".CRT$XP"},
        {"__xt_a", "__xt_z", ".CRT$XT"},
    }};
    for (const CrtSymRange& sr : kCrtSymRanges) {
        std::optional<std::uint64_t> begin_va;
        std::optional<std::uint64_t> end_va;
        for (const Symbol& sym : image->symbols()) {
            if (symbol_matches_identifier(sym.name, sr.start_sym)) {
                begin_va = sym.virtual_address;
            } else if (symbol_matches_identifier(sym.name, sr.end_sym)) {
                end_va = sym.virtual_address;
            }
        }
        if (begin_va && end_va && *end_va > *begin_va) {
            scan_crt_range(*begin_va, *end_va - *begin_va, sr.label);
        }
    }

    for (const Symbol& sym : image->symbols()) {
        std::string_view clean = strip_symbol_decorations(sym.name);
        if (clean.starts_with("___x")) {
            clean.remove_prefix(1);
        }
        if (sym.virtual_address == 0) {
            continue;
        }
        const bool is_crt_sym = clean.starts_with("__xi_") || clean.starts_with("__xc_") ||
                                clean.starts_with("__xp_") || clean.starts_with("__xt_");
        if (!is_crt_sym) {
            continue;
        }
        if (clean == "__xi_a" || clean == "__xi_z" || clean == "__xc_a" || clean == "__xc_z" ||
            clean == "__xp_a" || clean == "__xp_z" || clean == "__xt_a" || clean == "__xt_z") {
            continue;
        }
        if (seen_crt_slots.contains(sym.virtual_address)) {
            continue;
        }
        if (auto exec = ctx.is_executable_address(sym.virtual_address); exec && *exec) {
            seen_crt_slots.insert(sym.virtual_address);
            HandlerEntry e = make_entry(HandlerCategory::CrtInitializer,
                                        sym.name,
                                        sym.virtual_address,
                                        sym.name,
                                        std::string(describe_crt_prefix(clean)));
            e.record_address = sym.virtual_address;
            report.entries.push_back(std::move(e));
        } else {
            scan_crt_range(sym.virtual_address, ptr_size, sym.name);
        }
    }

    // 3. SafeSEH & GuardEH Continuation tables from LoadConfig
    primary_safeseh =
        extract_pe_safeseh_for_image(*image, ctx, true, &report.entries, static_partial);

    if (const PeLoadConfigDirectory* lc = image->pe_load_config_directory()) {
        if (lc->guard_eh_continuation_table != 0 && lc->guard_eh_continuation_count > 0) {
            const auto extra_stride = static_cast<std::size_t>((lc->guard_flags >> 28) & 0x0Fu);
            const std::size_t stride = 4u + extra_stride;
            const std::uint64_t table_va =
                (lc->guard_eh_continuation_table < image->image_base())
                    ? (image->image_base() + lc->guard_eh_continuation_table)
                    : lc->guard_eh_continuation_table;

            constexpr std::uint64_t kMaxGuardEh = 4096;
            const auto count =
                static_cast<std::size_t>(std::min(lc->guard_eh_continuation_count, kMaxGuardEh));
            const std::size_t byte_len = count * stride;
            if (auto buf = ctx.read_va(table_va, byte_len)) {
                const EndianReader reader(*buf, layout);
                for (std::size_t i = 0; i < count; ++i) {
                    const std::size_t off = i * stride;
                    const auto rva = reader.read_u32(off);
                    if (!rva) {
                        break;
                    }
                    if (*rva == 0) {
                        continue;
                    }
                    const std::uint64_t target_va =
                        image->image_base() + static_cast<std::uint64_t>(*rva);
                    std::string det = "LoadConfig GuardEHContinuationTable RVA " + hex_u64(*rva);
                    if (extra_stride > 0 && reader.can_read(off + 4u, extra_stride)) {
                        std::uint64_t meta = 0;
                        for (std::size_t m = 0; m < extra_stride && m < 8u; ++m) {
                            meta |= static_cast<std::uint64_t>((*buf)[off + 4u + m])
                                    << static_cast<unsigned int>(m * 8u);
                        }
                        det += " (metadata=" + hex_u64(meta) + ")";
                    }
                    HandlerEntry e = make_entry(HandlerCategory::PeGuardEhContinuation,
                                                "GuardEH[" + std::to_string(i) + "]",
                                                target_va,
                                                ctx.resolve_symbol(target_va),
                                                std::move(det));
                    e.record_address = table_va + static_cast<std::uint64_t>(off);
                    if (auto exec = ctx.is_executable_address(target_va)) {
                        e.validated_safe = *exec;
                    }
                    report.entries.push_back(std::move(e));
                }
            } else {
                static_partial = true;
            }
        }
    }

    // 4. Static Exception / VEH / VCH / atexit Imports & Symbols
    struct PeApiHookSpec {
        std::string_view api_name;
        HandlerCategory category;
        std::string_view description;
    };
    static constexpr std::array<PeApiHookSpec, 8> kPePlumbingApis{{
        {"SetUnhandledExceptionFilter",
         HandlerCategory::UnhandledExceptionFilter,
         "Win32 top-level unhandled exception filter registration API"},
        {"UnhandledExceptionFilter",
         HandlerCategory::UnhandledExceptionFilter,
         "Win32 unhandled exception dispatcher"},
        {"AddVectoredExceptionHandler",
         HandlerCategory::VehHandler,
         "Win32 Vectored Exception Handler registration import"},
        {"AddVectoredContinueHandler",
         HandlerCategory::VchHandler,
         "Win32 Vectored Continue Handler registration import"},
        {"_crt_atexit", HandlerCategory::AtexitHandler, "UCRT atexit registration API"},
        {"_register_onexit_function",
         HandlerCategory::AtexitHandler,
         "UCRT module onexit table registration API"},
        {"_onexit", HandlerCategory::AtexitHandler, "MSVCRT onexit registration API"},
        {"atexit", HandlerCategory::AtexitHandler, "Standard C atexit registration API"},
    }};

    std::unordered_set<std::string> seen_plumbing;
    for (const ImportEntry& imp : image->imports()) {
        if (imp.name.empty()) {
            continue;
        }
        for (const PeApiHookSpec& spec : kPePlumbingApis) {
            if (symbol_matches_identifier(imp.name, spec.api_name)) {
                const std::string key =
                    std::to_string(static_cast<unsigned int>(spec.category)) + ":" +
                    std::string(spec.api_name) + ":" + hex_u64(imp.address);
                if (!seen_plumbing.insert(key).second) {
                    break;
                }
                const std::string sym_label =
                    imp.library.empty() ? imp.name : (imp.library + "!" + imp.name);
                std::string det(spec.description);
                det += imp.delay_load ? " (delay-load IAT)" : " (IAT import)";
                HandlerEntry e = make_entry(
                    spec.category, imp.name, imp.address, sym_label, std::move(det));
                if (imp.address != 0) {
                    e.record_address = imp.address;
                }
                report.entries.push_back(std::move(e));
                break;
            }
        }
    }

    for (const Symbol& sym : image->symbols()) {
        if (sym.name.empty() || sym.virtual_address == 0) {
            continue;
        }
        for (const PeApiHookSpec& spec : kPePlumbingApis) {
            if (symbol_matches_identifier(sym.name, spec.api_name)) {
                const std::string key =
                    std::to_string(static_cast<unsigned int>(spec.category)) + ":" +
                    std::string(spec.api_name) + ":" + hex_u64(sym.virtual_address);
                if (!seen_plumbing.insert(key).second) {
                    break;
                }
                HandlerEntry e = make_entry(spec.category,
                                            sym.name,
                                            sym.virtual_address,
                                            sym.name,
                                            std::string(spec.description) + " (symbol)");
                e.record_address = sym.virtual_address;
                report.entries.push_back(std::move(e));
                break;
            }
        }
    }

    if (static_partial) {
        report.static_handlers_status = SubsystemStatus::partial(
            "pe-headers", "inspected PE static handler tables with partial byte reads");
    } else {
        report.static_handlers_status = SubsystemStatus::available(
            "pe-headers", "inspected PE TLS, CRT, LoadConfig, and handler imports");
    }

    // 5. PE .pdata / .xdata Unwind Exception & Termination Handlers
    const auto& rfs = image->pe_runtime_functions();
    if (rfs.empty()) {
        if (!image->is_64bit() && image->architecture() == Architecture::X86) {
            if (primary_safeseh.no_seh) {
                report.unwind_handlers_status = SubsystemStatus::available(
                    "pe-seh32", "32-bit x86 PE specifies IMAGE_DLLCHARACTERISTICS_NO_SEH");
            } else if (primary_safeseh.has_safeseh_table) {
                report.unwind_handlers_status = SubsystemStatus::available(
                    "pe-safeseh",
                    "32-bit x86 SafeSEH table (" +
                        std::to_string(primary_safeseh.safe_handlers.size()) + " handlers)");
            } else {
                report.unwind_handlers_status = SubsystemStatus::available(
                    "pe-seh32", "32-bit x86 PE uses stack-based SEH (no SafeSEH table)");
            }
        } else {
            report.unwind_handlers_status = SubsystemStatus::available(
                "pe-pdata", "no .pdata runtime function entries in image");
        }
        return;
    }

    constexpr std::size_t kMaxEmittedUnwindHandlers = 2048;
    std::size_t emitted_unwind = 0;
    std::size_t unwind_read_failures = 0;
    const bool is_arm64 = (image->architecture() == Architecture::ARM64);

    for (std::size_t idx = 0; idx < rfs.size() && emitted_unwind < kMaxEmittedUnwindHandlers;
         ++idx) {
        const PeRuntimeFunction& rf = rfs[idx];
        if (rf.unwind_info_rva == 0) {
            continue;
        }

        if (is_arm64) {
            // ARM64 .pdata: Flag bits [1:0] != 0 means packed unwind info (no exception handler).
            if ((rf.unwind_info_rva & 0x3u) != 0) {
                continue;
            }
            const std::uint64_t xdata_va =
                image->image_base() + static_cast<std::uint64_t>(rf.unwind_info_rva);
            auto hdr_buf = ctx.read_va(xdata_va, 8u);
            if (!hdr_buf) {
                ++unwind_read_failures;
                continue;
            }
            const EndianReader xr(*hdr_buf, layout);
            const auto word0 = xr.read_u32(0);
            if (!word0) {
                continue;
            }
            constexpr std::uint32_t kArm64XBit = (1u << 20);
            if ((*word0 & kArm64XBit) == 0) {
                continue;
            }
            const bool e_bit = (*word0 & (1u << 21)) != 0;
            std::uint32_t epilog_count = (*word0 >> 22) & 0x1Fu;
            std::uint32_t code_words = (*word0 >> 27) & 0x1Fu;
            std::size_t cursor = 4u;
            if (epilog_count == 0 && code_words == 0) {
                const auto word1 = xr.read_u32(4u);
                if (!word1) {
                    continue;
                }
                epilog_count = *word1 & 0xFFFFu;
                code_words = (*word1 >> 16) & 0xFFu;
                cursor = 8u;
            }
            const std::size_t scope_words = e_bit ? 0u : static_cast<std::size_t>(epilog_count);
            const std::size_t handler_off =
                cursor + (scope_words + static_cast<std::size_t>(code_words)) * 4u;
            const std::uint64_t handler_rva_addr =
                xdata_va + static_cast<std::uint64_t>(handler_off);
            auto hbuf = ctx.read_va(handler_rva_addr, 4u);
            if (!hbuf) {
                ++unwind_read_failures;
                continue;
            }
            const EndianReader hr(*hbuf, layout);
            const auto handler_rva = hr.read_u32(0);
            if (!handler_rva || *handler_rva == 0) {
                continue;
            }
            const std::uint64_t handler_va =
                image->image_base() + static_cast<std::uint64_t>(*handler_rva);
            const std::uint64_t scope_begin =
                image->image_base() + static_cast<std::uint64_t>(rf.begin_address_rva);
            HandlerEntry e = make_entry(HandlerCategory::PeUnwindException,
                                        ".pdata[" + std::to_string(idx) + "]",
                                        handler_va,
                                        ctx.resolve_symbol(handler_va),
                                        "ARM64 .xdata exception handler");
            e.record_address = xdata_va;
            e.scope_start = scope_begin;
            e.scope_end = image->image_base() + static_cast<std::uint64_t>(rf.end_address_rva);
            e.lsda_or_data_address = handler_rva_addr + 4u;
            if (auto exec = ctx.is_executable_address(handler_va)) {
                e.validated_safe = *exec;
            }
            report.entries.push_back(std::move(e));
            ++emitted_unwind;
            continue;
        }

        // Standard x64 PE RUNTIME_FUNCTION -> UNWIND_INFO
        if ((rf.unwind_info_rva & 0x1u) != 0) {
            // Bit 0 indicates a chained RUNTIME_FUNCTION entry rather than UNWIND_INFO.
            continue;
        }

        const std::uint64_t unwind_va =
            image->image_base() + static_cast<std::uint64_t>(rf.unwind_info_rva);
        auto head_buf = ctx.read_va(unwind_va, 4u);
        if (!head_buf) {
            ++unwind_read_failures;
            continue;
        }

        const std::uint8_t ver_flags = (*head_buf)[0];
        const std::uint8_t prolog_size = (*head_buf)[1];
        const std::uint8_t count_of_codes = (*head_buf)[2];
        const auto version = static_cast<std::uint8_t>(ver_flags & 0x07u);
        const auto flags = static_cast<std::uint8_t>(ver_flags >> 3);

        constexpr std::uint8_t kUnwFlagEHandler = 0x01u;
        constexpr std::uint8_t kUnwFlagUHandler = 0x02u;
        constexpr std::uint8_t kUnwFlagChainInfo = 0x04u;
        if ((flags & (kUnwFlagEHandler | kUnwFlagUHandler)) == 0 ||
            (flags & kUnwFlagChainInfo) != 0) {
            continue;
        }

        // Unwind codes are u16 entries padded to an even u16 count (4-byte aligned).
        const std::size_t padded_codes =
            (static_cast<std::size_t>(count_of_codes) + 1u) & ~std::size_t{1u};
        const std::size_t handler_rva_offset = 4u + padded_codes * 2u;
        const std::uint64_t handler_rva_addr =
            unwind_va + static_cast<std::uint64_t>(handler_rva_offset);

        auto hbuf = ctx.read_va(handler_rva_addr, 4u);
        if (!hbuf) {
            ++unwind_read_failures;
            continue;
        }
        const EndianReader hr(*hbuf, layout);
        const auto handler_rva = hr.read_u32(0);
        if (!handler_rva || *handler_rva == 0) {
            continue;
        }

        const std::uint64_t handler_va =
            image->image_base() + static_cast<std::uint64_t>(*handler_rva);
        const std::uint64_t scope_begin =
            image->image_base() + static_cast<std::uint64_t>(rf.begin_address_rva);
        const std::uint64_t scope_finish =
            image->image_base() + static_cast<std::uint64_t>(rf.end_address_rva);

        std::string flag_label;
        if ((flags & kUnwFlagEHandler) != 0 && (flags & kUnwFlagUHandler) != 0) {
            flag_label = "UNW_FLAG_EHANDLER|UNW_FLAG_UHANDLER";
        } else if ((flags & kUnwFlagEHandler) != 0) {
            flag_label = "UNW_FLAG_EHANDLER";
        } else {
            flag_label = "UNW_FLAG_UHANDLER";
        }

        std::string func_sym = ctx.resolve_symbol(scope_begin);
        std::string entry_name =
            !func_sym.empty() ? (".pdata " + func_sym) : (".pdata[" + std::to_string(idx) + "]");
        std::string det = flag_label + " (UNWIND_INFO v" + std::to_string(version) +
                          ", prolog=" + std::to_string(prolog_size) + "B)";

        HandlerEntry e = make_entry(HandlerCategory::PeUnwindException,
                                    std::move(entry_name),
                                    handler_va,
                                    ctx.resolve_symbol(handler_va),
                                    std::move(det));
        e.record_address = unwind_va;
        e.scope_start = scope_begin;
        e.scope_end = scope_finish;
        e.lsda_or_data_address = handler_rva_addr + 4u;
        if (auto exec = ctx.is_executable_address(handler_va)) {
            e.validated_safe = *exec;
        }
        report.entries.push_back(std::move(e));
        ++emitted_unwind;
    }

    if (unwind_read_failures > 0 && emitted_unwind == 0) {
        report.unwind_handlers_status = SubsystemStatus::partial(
            "pe-pdata", "failed to read UNWIND_INFO payloads from .xdata");
    } else if (unwind_read_failures > 0) {
        report.unwind_handlers_status = SubsystemStatus::partial(
            "pe-pdata",
            "decoded " + std::to_string(emitted_unwind) + " .pdata/.xdata handlers (" +
                std::to_string(unwind_read_failures) + " unreadable)");
    } else {
        report.unwind_handlers_status = SubsystemStatus::available(
            "pe-pdata",
            "inspected " + std::to_string(rfs.size()) + " .pdata entries (" +
                std::to_string(emitted_unwind) + " with exception/termination handlers)");
    }
}

[[nodiscard]] std::uint64_t rtl_decode_pointer_for_target(
    std::uint64_t encoded,
    std::uint64_t cookie,
    const HandlerInspectorContext& ctx) noexcept {
    if (ctx.layout().is_64bit()) {
        const auto shift = static_cast<int>(cookie & 0x3Full);
        const std::uint64_t primary = std::rotr(encoded ^ cookie, shift);
        const std::uint64_t alt = std::rotl(encoded, shift) ^ cookie;
        const auto p_exec = ctx.is_executable_address(primary);
        if (p_exec.has_value() && *p_exec) {
            return primary;
        }
        const auto a_exec = ctx.is_executable_address(alt);
        if (p_exec.has_value() && !*p_exec && a_exec.has_value() && *a_exec) {
            return alt;
        }
        return primary;
    }

    const auto enc32 = static_cast<std::uint32_t>(encoded & 0xFFFF'FFFFull);
    const auto c32 = static_cast<std::uint32_t>(cookie & 0xFFFF'FFFFull);
    const auto shift = static_cast<int>(c32 & 0x1Fu);
    const std::uint32_t primary = std::rotr(enc32 ^ c32, shift);
    const std::uint32_t alt = std::rotl(enc32, shift) ^ c32;
    const auto p_exec = ctx.is_executable_address(primary);
    if (p_exec.has_value() && *p_exec) {
        return primary;
    }
    const auto a_exec = ctx.is_executable_address(alt);
    if (p_exec.has_value() && !*p_exec && a_exec.has_value() && *a_exec) {
        return alt;
    }
    return primary;
}

void inspect_pe_live_handlers(HandlerInspectorContext& ctx,
                              const PeModuleSafeSehInfo& primary_safeseh,
                              HandlersReport& report) {
    IProcessSession* session = ctx.session();
    if (session == nullptr) {
        report.live_seh_veh_status =
            SubsystemStatus::unavailable("pe-live", "no live process session attached");
        return;
    }

    const TargetLayout layout = ctx.layout();
    const std::size_t ptr_size = layout.pointer_size();
    bool seh32_ok = false;
    bool seh32_attempted = false;
    std::string seh32_summary;

    // 1. 32-bit x86 Live SEH Chain from TEB32.ExceptionList (teb + 0x00)
    if (!layout.is_64bit()) {
        std::optional<std::uint64_t> teb_va;
        std::optional<std::uint64_t> stack_sp;
        if (const ThreadContext* tc = ctx.selected_thread()) {
            if (tc->teb_address.has_value() && *tc->teb_address != 0) {
                teb_va = *tc->teb_address;
            } else if (tc->tls_pointer.has_value() && *tc->tls_pointer != 0) {
                teb_va = *tc->tls_pointer;
            }
            if (tc->stack_pointer != 0) {
                stack_sp = tc->stack_pointer;
            }
        }
        if (!teb_va.has_value()) {
            if (auto threads = session->threads(); threads && !threads->empty()) {
                for (const ThreadInfo& ti : *threads) {
                    if (ti.teb_address.has_value() && *ti.teb_address != 0) {
                        teb_va = *ti.teb_address;
                        stack_sp = ti.stack_pointer;
                        break;
                    }
                    if (ti.tls_base.has_value() && *ti.tls_base != 0) {
                        teb_va = *ti.tls_base;
                        stack_sp = ti.stack_pointer;
                        break;
                    }
                }
            }
        }

        if (teb_va.has_value() && *teb_va != 0) {
            seh32_attempted = true;
            std::optional<MemoryRegion> thread_stack_region;
            if (stack_sp.has_value()) {
                for (const MemoryRegion& reg : ctx.regions()) {
                    if (reg.contains(*stack_sp)) {
                        thread_stack_region = reg;
                        break;
                    }
                }
            }

            std::unordered_map<std::uint64_t, PeModuleSafeSehInfo> mod_safeseh_cache;
            const auto validate_seh32_handler =
                [&](std::uint64_t record_va,
                    std::uint64_t handler_va) -> std::pair<bool, std::string> {
                bool record_ok = true;
                std::string prefix;
                if (thread_stack_region.has_value() && !thread_stack_region->contains(record_va)) {
                    record_ok = false;
                    prefix = "SEH record outside thread stack; ";
                }

                const auto eval_against_module =
                    [&](const PeModuleSafeSehInfo& msi,
                        std::string_view mod_label) -> std::pair<bool, std::string> {
                    if (msi.no_seh) {
                        return {false,
                                prefix + std::string(mod_label) +
                                    " sets IMAGE_DLLCHARACTERISTICS_NO_SEH"};
                    }
                    if (msi.has_safeseh_table) {
                        const bool in_table = msi.safe_handlers.contains(handler_va);
                        return {record_ok && in_table,
                                prefix + (in_table ? "verified in SafeSEH table"
                                                   : "NOT in module SafeSEH table")};
                    }
                    const auto exec = ctx.is_executable_address(handler_va);
                    if (exec.has_value() && !*exec) {
                        return {false, prefix + "handler outside executable section"};
                    }
                    return {record_ok,
                            prefix + "executable handler (module built without SafeSEH table)"};
                };

                if (ctx.image() != nullptr && ctx.image_contains_va(*ctx.image(), handler_va)) {
                    return eval_against_module(primary_safeseh, "image");
                }

                for (const ModuleInfo& mod : ctx.modules()) {
                    if (!mod.contains(handler_va)) {
                        continue;
                    }
                    auto cached = mod_safeseh_cache.find(mod.base_address);
                    if (cached == mod_safeseh_cache.end()) {
                        PeModuleSafeSehInfo msi;
                        if (const IBinaryImage* mimg = ctx.get_or_load_module_image(mod)) {
                            bool dummy_fail = false;
                            msi = extract_pe_safeseh_for_image(
                                *mimg, ctx, false, nullptr, dummy_fail);
                        }
                        cached = mod_safeseh_cache.emplace(mod.base_address, std::move(msi)).first;
                    }
                    if (cached->second.is_pe) {
                        return eval_against_module(cached->second, mod.name);
                    }
                    const auto exec = ctx.is_executable_address(handler_va);
                    const bool ok = record_ok && (!exec.has_value() || *exec);
                    return {ok,
                            prefix + (ok ? ("within module " + mod.name)
                                         : ("non-executable address in " + mod.name))};
                }

                if (thread_stack_region.has_value() && thread_stack_region->contains(handler_va)) {
                    return {false, prefix + "unsafe stack-resident SEH handler"};
                }
                const auto exec = ctx.is_executable_address(handler_va);
                if (exec.has_value()) {
                    if (!*exec) {
                        return {false, prefix + "non-executable unbacked handler address"};
                    }
                    if (!ctx.modules().empty()) {
                        return {false, prefix + "executable memory outside loaded modules"};
                    }
                    return {record_ok, prefix + "executable region"};
                }
                return {record_ok, prefix + "unverified module bounds"};
            };

            if (auto head_bytes = ctx.read_live_va(*teb_va, 4u)) {
                const EndianReader tr(*head_bytes, layout);
                const auto head = tr.read_u32(0);
                if (head) {
                    seh32_ok = true;
                    std::uint32_t curr = *head;
                    constexpr std::size_t kMaxSehNodes = 64;
                    std::unordered_set<std::uint32_t> visited;
                    std::size_t depth = 0;
                    while (curr != 0xFFFF'FFFFu && curr != 0u && depth < kMaxSehNodes) {
                        if (!visited.insert(curr).second) {
                            seh32_summary = "cycle detected in SEH chain";
                            break;
                        }
                        auto rec_bytes = ctx.read_live_va(static_cast<std::uint64_t>(curr), 8u);
                        if (!rec_bytes) {
                            seh32_summary = "truncated SEH chain at " + hex_u64(curr, 8);
                            break;
                        }
                        const EndianReader rr(*rec_bytes, layout);
                        const auto next = rr.read_u32(0);
                        const auto handler = rr.read_u32(4u);
                        if (!next || !handler) {
                            break;
                        }

                        const auto handler_va = static_cast<std::uint64_t>(*handler);
                        auto [is_safe, note] =
                            validate_seh32_handler(static_cast<std::uint64_t>(curr), handler_va);

                        HandlerEntry e = make_entry(
                            HandlerCategory::SehChain32,
                            "SEH[" + std::to_string(depth) + "]",
                            handler_va,
                            ctx.resolve_symbol(handler_va),
                            "Next=" + hex_u64(*next, 8) + "; " + note);
                        e.record_address = static_cast<std::uint64_t>(curr);
                        e.validated_safe = is_safe;
                        report.entries.push_back(std::move(e));

                        curr = *next;
                        ++depth;
                    }
                    if (seh32_summary.empty()) {
                        seh32_summary =
                            "walked " + std::to_string(depth) + " 32-bit SEH registration record(s)";
                    }
                }
            } else {
                seh32_summary = "failed to read TEB32.ExceptionList at " + hex_u64(*teb_va, 8);
            }
        }
    }

    // 2. Windows Live VEH / VCH (ntdll!LdrpVectorHandlerList + optional ProcessCookie)
    struct VehSymbols {
        std::optional<std::uint64_t> list_va;
        std::optional<std::uint64_t> vch_separate_va;
        std::optional<std::uint64_t> cookie_va;
        std::uint64_t cookie_sym_size{0};
    };

    const auto scan_image_for_veh_symbols = [](const IBinaryImage& img, VehSymbols& out) {
        for (const Symbol& sym : img.symbols()) {
            if (sym.virtual_address == 0 || sym.name.empty()) {
                continue;
            }
            if (!out.list_va && symbol_matches_identifier(sym.name, "LdrpVectorHandlerList")) {
                out.list_va = sym.virtual_address;
            } else if (!out.vch_separate_va &&
                       symbol_matches_identifier(sym.name, "LdrpVectorContinueHandlerList")) {
                out.vch_separate_va = sym.virtual_address;
            } else if (!out.cookie_va && symbol_matches_identifier(sym.name, "ProcessCookie")) {
                out.cookie_va = sym.virtual_address;
                out.cookie_sym_size = sym.size;
            }
        }
        for (const ExportEntry& exp : img.exports()) {
            if (exp.virtual_address == 0 || exp.name.empty()) {
                continue;
            }
            if (!out.list_va && symbol_matches_identifier(exp.name, "LdrpVectorHandlerList")) {
                out.list_va = exp.virtual_address;
            } else if (!out.cookie_va && symbol_matches_identifier(exp.name, "ProcessCookie")) {
                out.cookie_va = exp.virtual_address;
            }
        }
    };

    VehSymbols veh_syms;
    if (ctx.image() != nullptr) {
        scan_image_for_veh_symbols(*ctx.image(), veh_syms);
    }
    if (!veh_syms.list_va.has_value()) {
        for (const ModuleInfo& mod : ctx.modules()) {
            if (iequals_ascii(mod.name, "ntdll.dll") || iequals_ascii(mod.name, "ntdll")) {
                if (const IBinaryImage* ntdll_img = ctx.get_or_load_module_image(mod)) {
                    scan_image_for_veh_symbols(*ntdll_img, veh_syms);
                }
                break;
            }
        }
    }

    if (!veh_syms.list_va.has_value()) {
        if (seh32_ok) {
            report.live_seh_veh_status = SubsystemStatus::partial(
                "pe-live", seh32_summary + "; ntdll!LdrpVectorHandlerList symbol not loaded");
        } else if (seh32_attempted) {
            report.live_seh_veh_status = SubsystemStatus::unavailable(
                "ntdll", seh32_summary + "; ntdll!LdrpVectorHandlerList symbol not loaded");
        } else {
            report.live_seh_veh_status = SubsystemStatus::unavailable(
                "ntdll", "ntdll!LdrpVectorHandlerList symbol not loaded");
        }
        return;
    }

    // Read ProcessCookie if available.
    std::optional<std::uint64_t> cookie_primary;
    std::optional<std::uint64_t> cookie_u32_alt;
    if (veh_syms.cookie_va.has_value() && *veh_syms.cookie_va != 0) {
        if (veh_syms.cookie_sym_size == 4u || !layout.is_64bit()) {
            if (auto cb = ctx.read_live_va(*veh_syms.cookie_va, 4u)) {
                const EndianReader cr(*cb, layout);
                if (auto c32 = cr.read_u32(0)) {
                    cookie_primary = static_cast<std::uint64_t>(*c32);
                }
            }
        } else {
            if (auto cb8 = ctx.read_live_va(*veh_syms.cookie_va, 8u)) {
                const EndianReader cr(*cb8, layout);
                const auto c64 = cr.read_u64(0);
                const auto c32 = cr.read_u32(0);
                if (c64) {
                    cookie_primary = *c64;
                }
                if (c32 && (!c64 || *c64 != static_cast<std::uint64_t>(*c32))) {
                    cookie_u32_alt = static_cast<std::uint64_t>(*c32);
                }
            } else if (auto cb4 = ctx.read_live_va(*veh_syms.cookie_va, 4u)) {
                const EndianReader cr(*cb4, layout);
                if (auto c32 = cr.read_u32(0)) {
                    cookie_primary = static_cast<std::uint64_t>(*c32);
                }
            }
        }
    }

    const auto decode_veh_ptr = [&](std::uint64_t raw_enc) -> std::pair<std::uint64_t, std::uint64_t> {
        const std::uint64_t c_main = *cookie_primary;
        const std::uint64_t d_main = rtl_decode_pointer_for_target(raw_enc, c_main, ctx);
        if (cookie_u32_alt.has_value()) {
            const auto main_exec = ctx.is_executable_address(d_main);
            if (main_exec.has_value() && !*main_exec) {
                const std::uint64_t d_alt =
                    rtl_decode_pointer_for_target(raw_enc, *cookie_u32_alt, ctx);
                const auto alt_exec = ctx.is_executable_address(d_alt);
                if (alt_exec.has_value() && *alt_exec) {
                    return {d_alt, *cookie_u32_alt};
                }
            }
        }
        return {d_main, c_main};
    };

    const auto node_links_to_head = [&](std::uint64_t node_va, std::uint64_t head_va) -> bool {
        if (node_va == 0 || node_va == head_va) {
            return node_va == head_va;
        }
        auto nb = ctx.read_live_va(node_va, 2u * ptr_size);
        if (!nb) {
            return false;
        }
        const EndianReader nr(*nb, layout);
        const auto w0 = nr.read_pointer(0);
        const auto w1 = nr.read_pointer(ptr_size);
        return (w0 && *w0 == head_va) || (w1 && *w1 == head_va);
    };

    // Detect whether LdrpVectorHandlerList starts with SRWLOCK (standard Windows:
    // { SRWLOCK Lock; LIST_ENTRY List; } = 3 * ptr_size) or bare LIST_ENTRY (2 * ptr_size).
    const std::uint64_t base_va = *veh_syms.list_va;
    bool has_srwlock_header = true;
    if (auto probe = ctx.read_live_va(base_va, 3u * ptr_size)) {
        const EndianReader pr(*probe, layout);
        const std::uint64_t w0 = pr.read_pointer(0).value_or(0);
        const std::uint64_t w1 = pr.read_pointer(ptr_size).value_or(0);
        const std::uint64_t w2 = pr.read_pointer(2u * ptr_size).value_or(0);
        const std::uint64_t srw_head = base_va + static_cast<std::uint64_t>(ptr_size);
        if (w1 == srw_head && w2 == srw_head) {
            has_srwlock_header = true;
        } else if (w0 == base_va && w1 == base_va) {
            has_srwlock_header = false;
        } else if (node_links_to_head(w1, srw_head)) {
            has_srwlock_header = true;
        } else if (node_links_to_head(w0, base_va) || node_links_to_head(w1, base_va)) {
            has_srwlock_header = false;
        }
    } else if (ctx.read_live_va(base_va, 2u * ptr_size).has_value()) {
        has_srwlock_header = false;
    }

    const std::uint64_t list_stride =
        static_cast<std::uint64_t>((has_srwlock_header ? 3u : 2u) * ptr_size);
    const std::uint64_t veh_head_va =
        base_va + static_cast<std::uint64_t>(has_srwlock_header ? ptr_size : 0u);
    const std::uint64_t vch_head_va =
        veh_syms.vch_separate_va.has_value()
            ? (*veh_syms.vch_separate_va +
               static_cast<std::uint64_t>(has_srwlock_header ? ptr_size : 0u))
            : (veh_head_va + list_stride);

    bool any_list_read = false;
    bool any_undecoded = false;
    std::size_t total_veh_vch = 0;

    const auto walk_vector_list =
        [&](std::uint64_t head_va, HandlerCategory cat, std::string_view prefix, bool optional_list) {
            auto head_buf = ctx.read_live_va(head_va, 2u * ptr_size);
            if (!head_buf) {
                return;
            }
            const EndianReader hr(*head_buf, layout);
            const auto hw0 = hr.read_pointer(0);
            const auto hw1 = hr.read_pointer(ptr_size);
            if (!hw0 || !hw1) {
                return;
            }

            // Empty circular list: both links point to head_va.
            if (*hw0 == head_va && *hw1 == head_va) {
                any_list_read = true;
                return;
            }
            if (*hw0 == 0 && *hw1 == 0) {
                if (!optional_list) {
                    any_list_read = true;
                }
                return;
            }

            // Determine forward link offset: +0 for standard LIST_ENTRY {Flink, Blink},
            // or +ptr_size if a mock constructed {Blink, Flink}.
            std::size_t step_link_offset = 0u;
            std::uint64_t first_node = *hw0;
            if (*hw0 == 0 && *hw1 != 0 && *hw1 != head_va) {
                step_link_offset = ptr_size;
                first_node = *hw1;
            } else if (auto first_probe = ctx.read_live_va(*hw0, 2u * ptr_size)) {
                const EndianReader fnr(*first_probe, layout);
                const std::uint64_t fw0 = fnr.read_pointer(0).value_or(0);
                const std::uint64_t fw1 = fnr.read_pointer(ptr_size).value_or(0);
                if (fw1 == head_va) {
                    step_link_offset = 0u;
                    first_node = *hw0;
                } else if (fw0 == head_va && *hw1 != *hw0) {
                    step_link_offset = ptr_size;
                    first_node = *hw1;
                } else if (optional_list && fw0 != head_va && fw1 != head_va) {
                    return;
                }
            } else if (optional_list) {
                return;
            }

            any_list_read = true;
            std::unordered_set<std::uint64_t> visited;
            std::uint64_t curr = first_node;
            constexpr std::size_t kMaxVehNodes = 64;
            std::size_t idx = 0;

            while (curr != 0 && curr != head_va && idx < kMaxVehNodes) {
                if (!visited.insert(curr).second) {
                    break;
                }
                // VECTORED_HANDLER_ENTRY has encoded handler at +3*ptr_size (Win7/8/classic)
                // or +4*ptr_size (Win10/11 where +3*ptr_size is 0).
                std::optional<std::vector<std::uint8_t>> node_buf =
                    ctx.read_live_va(curr, 5u * ptr_size);
                if (!node_buf) {
                    node_buf = ctx.read_live_va(curr, 4u * ptr_size);
                }
                if (!node_buf) {
                    break;
                }
                const EndianReader nr(*node_buf, layout);
                const auto next_node = nr.read_pointer(step_link_offset);
                const auto cand3 = nr.read_pointer(3u * ptr_size);
                if (!next_node || !cand3) {
                    break;
                }

                std::uint64_t encoded_ptr = *cand3;
                if (nr.can_read(4u * ptr_size, ptr_size)) {
                    const std::uint64_t cand4 = nr.read_pointer(4u * ptr_size).value_or(0);
                    if (encoded_ptr == 0 && cand4 != 0) {
                        encoded_ptr = cand4;
                    } else if (encoded_ptr != 0 && cand4 != 0 && cookie_primary.has_value()) {
                        auto [dec3, ck3] = decode_veh_ptr(encoded_ptr);
                        auto [dec4, ck4] = decode_veh_ptr(cand4);
                        (void)ck3;
                        (void)ck4;
                        const auto ex3 = ctx.is_executable_address(dec3);
                        const auto ex4 = ctx.is_executable_address(dec4);
                        if (ex3.has_value() && !*ex3 && ex4.has_value() && *ex4) {
                            encoded_ptr = cand4;
                        }
                    }
                }

                HandlerEntry e;
                e.category = cat;
                e.category_label = std::string(to_string(cat));
                e.name = std::string(prefix) + "[" + std::to_string(idx) + "]";
                e.record_address = curr;
                e.pointer_encoded = true;

                if (cookie_primary.has_value()) {
                    const auto [decoded_va, used_cookie] = decode_veh_ptr(encoded_ptr);
                    e.handler_address = decoded_va;
                    e.pointer_decoded = true;
                    e.symbol_name = ctx.resolve_symbol(decoded_va);
                    if (auto exec = ctx.is_executable_address(decoded_va)) {
                        e.validated_safe = *exec;
                    }
                    e.detail = "RtlDecodePointer(encoded=" + hex_u64(encoded_ptr) +
                               ", cookie=" + hex_u64(used_cookie) + ")";
                } else {
                    any_undecoded = true;
                    e.handler_address = encoded_ptr;
                    e.pointer_decoded = false;
                    e.detail = "Encoded=" + hex_u64(encoded_ptr) +
                               " (ProcessCookie unavailable; pointer not decoded)";
                }

                report.entries.push_back(std::move(e));
                ++idx;
                ++total_veh_vch;
                curr = *next_node;
            }
        };

    walk_vector_list(veh_head_va, HandlerCategory::VehHandler, "VEH", false);
    walk_vector_list(vch_head_va, HandlerCategory::VchHandler, "VCH", true);

    if (!any_list_read) {
        report.live_seh_veh_status =
            seh32_ok
                ? SubsystemStatus::partial(
                      "pe-live",
                      seh32_summary + "; failed to read ntdll!LdrpVectorHandlerList memory")
                : SubsystemStatus::unavailable(
                      "ntdll", "failed to read ntdll!LdrpVectorHandlerList memory");
    } else if (any_undecoded) {
        report.live_seh_veh_status = SubsystemStatus::partial(
            "ntdll",
            "walked " + std::to_string(total_veh_vch) +
                " VEH/VCH entry(s); ProcessCookie unavailable for RtlDecodePointer");
    } else {
        std::string det =
            "inspected VEH/VCH lists (" + std::to_string(total_veh_vch) + " active handler(s))";
        if (!seh32_summary.empty()) {
            det = seh32_summary + "; " + det;
        }
        report.live_seh_veh_status = SubsystemStatus::available("pe-live", std::move(det));
    }
}

// ---------------------------------------------------------------------------
// ELF Init/Fini & DWARF/LSB .eh_frame CIE/FDE Personality + LSDA Parser
// ---------------------------------------------------------------------------

[[nodiscard]] std::optional<std::uint64_t> read_uleb128(std::span<const std::uint8_t> buf,
                                                        std::size_t& cursor) noexcept {
    std::uint64_t result = 0;
    unsigned int shift = 0;
    for (std::size_t i = 0; i < 10u; ++i) {
        if (cursor >= buf.size()) {
            return std::nullopt;
        }
        const std::uint8_t byte = buf[cursor++];
        if (shift < 64u) {
            const auto low = static_cast<std::uint64_t>(byte & 0x7Fu);
            if (shift == 63u && low > 1u) {
                return std::nullopt;
            }
            result |= (low << shift);
        }
        if ((byte & 0x80u) == 0) {
            return result;
        }
        shift += 7u;
    }
    return std::nullopt;
}

[[nodiscard]] std::optional<std::int64_t> read_sleb128(std::span<const std::uint8_t> buf,
                                                       std::size_t& cursor) noexcept {
    std::uint64_t result = 0;
    unsigned int shift = 0;
    std::uint8_t byte = 0;
    for (std::size_t i = 0; i < 10u; ++i) {
        if (cursor >= buf.size()) {
            return std::nullopt;
        }
        byte = buf[cursor++];
        if (shift < 64u) {
            result |= (static_cast<std::uint64_t>(byte & 0x7Fu) << shift);
        }
        shift += 7u;
        if ((byte & 0x80u) == 0) {
            if (shift < 64u && (byte & 0x40u) != 0) {
                result |= (~std::uint64_t{0} << shift);
            }
            return static_cast<std::int64_t>(result);
        }
    }
    return std::nullopt;
}

struct DecodedEhPointer {
    std::uint64_t address{0};
    std::string symbol_hint;
};

struct EhDecodeBases {
    std::uint64_t eh_frame_va{0};
    std::uint64_t text_base{0};
    std::uint64_t datarel_base{0};
    std::uint64_t func_base{0};
};

[[nodiscard]] std::optional<DecodedEhPointer> decode_dw_eh_pe(
    std::uint8_t encoding,
    const EndianReader& reader,
    std::size_t& cursor,
    const EhDecodeBases& bases,
    HandlerInspectorContext& ctx,
    bool size_only = false) {
    constexpr std::uint8_t kDwEhPeOmit = 0xFFu;
    constexpr std::uint8_t kDwEhPeAligned = 0x50u;
    if (encoding == kDwEhPeOmit) {
        return DecodedEhPointer{0, {}};
    }

    const TargetLayout layout = reader.layout();
    const std::size_t ptr_size = layout.pointer_size();
    const std::uint64_t field_va = bases.eh_frame_va + static_cast<std::uint64_t>(cursor);

    if (!size_only && encoding == kDwEhPeAligned) {
        const std::uint64_t rem = field_va % static_cast<std::uint64_t>(ptr_size);
        if (rem != 0) {
            const auto pad = static_cast<std::size_t>(static_cast<std::uint64_t>(ptr_size) - rem);
            if (pad > reader.size() - cursor) {
                return std::nullopt;
            }
            cursor += pad;
        }
        const auto val = reader.read_pointer(cursor);
        if (!val) {
            return std::nullopt;
        }
        cursor += ptr_size;
        return DecodedEhPointer{*val, {}};
    }

    const auto format = static_cast<std::uint8_t>(encoding & 0x0Fu);
    std::uint64_t raw = 0;
    std::int64_t signed_disp = 0;
    bool is_signed_format = false;
    switch (format) {
        case 0x00u: {  // DW_EH_PE_absptr
            const auto v = reader.read_pointer(cursor);
            if (!v) {
                return std::nullopt;
            }
            raw = *v;
            cursor += ptr_size;
            break;
        }
        case 0x01u: {  // DW_EH_PE_uleb128
            const auto v = read_uleb128(reader.bytes(), cursor);
            if (!v) {
                return std::nullopt;
            }
            raw = *v;
            break;
        }
        case 0x02u: {  // DW_EH_PE_udata2
            const auto v = reader.read_u16(cursor);
            if (!v) {
                return std::nullopt;
            }
            raw = *v;
            cursor += 2u;
            break;
        }
        case 0x03u: {  // DW_EH_PE_udata4
            const auto v = reader.read_u32(cursor);
            if (!v) {
                return std::nullopt;
            }
            raw = *v;
            cursor += 4u;
            break;
        }
        case 0x04u: {  // DW_EH_PE_udata8
            const auto v = reader.read_u64(cursor);
            if (!v) {
                return std::nullopt;
            }
            raw = *v;
            cursor += 8u;
            break;
        }
        case 0x09u: {  // DW_EH_PE_sleb128
            const auto v = read_sleb128(reader.bytes(), cursor);
            if (!v) {
                return std::nullopt;
            }
            signed_disp = *v;
            raw = static_cast<std::uint64_t>(*v);
            is_signed_format = true;
            break;
        }
        case 0x0Au: {  // DW_EH_PE_sdata2
            const auto v = reader.read_i16(cursor);
            if (!v) {
                return std::nullopt;
            }
            signed_disp = static_cast<std::int64_t>(*v);
            raw = static_cast<std::uint64_t>(signed_disp);
            is_signed_format = true;
            cursor += 2u;
            break;
        }
        case 0x0Bu: {  // DW_EH_PE_sdata4
            const auto v = reader.read_i32(cursor);
            if (!v) {
                return std::nullopt;
            }
            signed_disp = static_cast<std::int64_t>(*v);
            raw = static_cast<std::uint64_t>(signed_disp);
            is_signed_format = true;
            cursor += 4u;
            break;
        }
        case 0x0Cu: {  // DW_EH_PE_sdata8
            const auto v = reader.read_i64(cursor);
            if (!v) {
                return std::nullopt;
            }
            signed_disp = *v;
            raw = static_cast<std::uint64_t>(*v);
            is_signed_format = true;
            cursor += 8u;
            break;
        }
        default:
            return std::nullopt;
    }

    if (size_only) {
        if (is_signed_format && signed_disp < 0) {
            return std::nullopt;
        }
        return DecodedEhPointer{raw, {}};
    }
    if (raw == 0) {
        return DecodedEhPointer{0, {}};
    }

    const auto apply_rel_base = [&](std::uint64_t rel_base) -> std::optional<std::uint64_t> {
        if (is_signed_format) {
            return checked_apply_signed_displacement(rel_base, signed_disp, layout.is_64bit());
        }
        if (raw > std::numeric_limits<std::uint64_t>::max() - rel_base) {
            return std::nullopt;
        }
        const std::uint64_t sum = rel_base + raw;
        if (!layout.is_64bit() && sum > 0xFFFF'FFFFull) {
            return std::nullopt;
        }
        return sum;
    };

    const auto application = static_cast<std::uint8_t>(encoding & 0x70u);
    std::optional<std::uint64_t> resolved_addr;
    switch (application) {
        case 0x00u:  // DW_EH_PE_absptr
            if (is_signed_format && signed_disp < 0) {
                return std::nullopt;
            }
            if (!layout.is_64bit() && raw > 0xFFFF'FFFFull) {
                return std::nullopt;
            }
            resolved_addr = raw;
            break;
        case 0x10u:  // DW_EH_PE_pcrel
            resolved_addr = apply_rel_base(field_va);
            break;
        case 0x20u:  // DW_EH_PE_textrel
            resolved_addr = apply_rel_base(bases.text_base);
            break;
        case 0x30u:  // DW_EH_PE_datarel
            resolved_addr = apply_rel_base(bases.datarel_base);
            break;
        case 0x40u:  // DW_EH_PE_funcrel
            resolved_addr = apply_rel_base(bases.func_base);
            break;
        default:
            return std::nullopt;
    }
    if (!resolved_addr) {
        return std::nullopt;
    }
    const std::uint64_t addr = *resolved_addr;

    DecodedEhPointer out{addr, {}};
    if ((encoding & 0x80u) != 0) {  // DW_EH_PE_indirect
        const std::uint64_t indirect_slot = addr;
        // Prefer live memory when attached because .data.rel.ro / GOT is relocated by ld.so.
        if (auto slot_bytes = ctx.read_va(indirect_slot, ptr_size, ctx.session() != nullptr)) {
            const EndianReader sr(*slot_bytes, layout);
            if (const auto deref = sr.read_pointer(0)) {
                if (*deref != 0) {
                    out.address = *deref;
                    out.symbol_hint = ctx.resolve_symbol(*deref);
                    return out;
                }
            }
        }

        // Unrelocated static PIE GOT/.data.rel.ro slot (e.g. DW.ref.__gxx_personality_v0):
        // inspect ELF relocations and local reference symbols at `indirect_slot`.
        if (const IBinaryImage* img = ctx.image()) {
            for (const ElfRelocation& rel : img->elf_relocations()) {
                if (rel.offset != indirect_slot) {
                    continue;
                }
                if (rel.symbol_index > 0 && rel.symbol_index < img->elf_symbols().size()) {
                    const ElfSymbol& es =
                        img->elf_symbols()[static_cast<std::size_t>(rel.symbol_index)];
                    if (!es.name.empty()) {
                        out.symbol_hint = es.name;
                    }
                    if (es.value != 0) {
                        if (const auto relocated = checked_apply_signed_displacement(
                                es.value, rel.addend, img->is_64bit())) {
                            out.address = *relocated;
                            return out;
                        }
                        return std::nullopt;
                    }
                } else if (rel.has_addend && rel.addend > 0) {
                    if (const auto relocated = checked_apply_signed_displacement(
                            img->image_base(), rel.addend, img->is_64bit())) {
                        out.address = *relocated;
                        return out;
                    }
                    return std::nullopt;
                }
            }
            for (const Symbol& sym : img->symbols()) {
                if (sym.virtual_address == indirect_slot && !sym.name.empty()) {
                    std::string_view n = sym.name;
                    if (n.starts_with("DW.ref.")) {
                        n.remove_prefix(7);
                    }
                    out.symbol_hint = std::string(n);
                    break;
                }
            }
        }
        out.address = indirect_slot;
    }

    return out;
}

[[nodiscard]] std::optional<std::uint64_t> resolve_elf_static_reloc_slot(
    const IBinaryImage& img,
    std::uint64_t slot_va) {
    for (const ElfRelocation& rel : img.elf_relocations()) {
        if (rel.offset != slot_va) {
            continue;
        }
        if (rel.symbol_index > 0 && rel.symbol_index < img.elf_symbols().size()) {
            const ElfSymbol& es = img.elf_symbols()[static_cast<std::size_t>(rel.symbol_index)];
            if (es.value != 0) {
                return checked_apply_signed_displacement(es.value, rel.addend, img.is_64bit());
            }
        } else if (rel.has_addend && rel.addend > 0) {
            const auto add = static_cast<std::uint64_t>(rel.addend);
            if (add < img.image_base()) {
                return checked_apply_signed_displacement(img.image_base(), rel.addend, img.is_64bit());
            }
            if (!img.is_64bit() && add > 0xFFFF'FFFFull) {
                return std::nullopt;
            }
            return add;
        }
    }
    return std::nullopt;
}

void inspect_elf_static_and_unwind(HandlerInspectorContext& ctx, HandlersReport& report) {
    const IBinaryImage* image = ctx.image();
    if (image == nullptr) {
        report.static_handlers_status =
            SubsystemStatus::unavailable("elf-headers", "no ELF image available");
        report.unwind_handlers_status =
            SubsystemStatus::unavailable("elf-eh-frame", "no ELF image available");
        return;
    }

    const TargetLayout layout = ctx.layout();
    const std::size_t ptr_size = layout.pointer_size();
    bool static_partial = false;

    // 1. ELF Init / Fini sections & pointer arrays + Dynamic tags fallback
    std::unordered_set<std::uint64_t> emitted_single_init_fini;
    std::unordered_set<std::uint64_t> emitted_array_slots;

    const auto emit_pointer_array = [&](std::uint64_t array_va,
                                        std::uint64_t array_size,
                                        std::uint64_t raw_file_off,
                                        bool has_raw_file_off,
                                        std::string_view label,
                                        bool skip_minus_one_sentinel) {
        if (array_size < ptr_size) {
            return;
        }
        constexpr std::size_t kMaxArrayEntries = 1024;
        const std::size_t clamped_bytes = static_cast<std::size_t>(std::min<std::uint64_t>(
            array_size, static_cast<std::uint64_t>(kMaxArrayEntries * ptr_size)));
        const std::size_t aligned_bytes = (clamped_bytes / ptr_size) * ptr_size;
        if (aligned_bytes == 0) {
            return;
        }

        std::optional<std::vector<std::uint8_t>> buf;
        if (array_va != 0) {
            // Prefer live memory if attached so PIE R_*_RELATIVE relocations are resolved.
            buf = ctx.read_va(array_va, aligned_bytes, ctx.session() != nullptr);
        } else if (has_raw_file_off && raw_file_off <= ctx.static_bytes().size() &&
                   aligned_bytes <= ctx.static_bytes().size() - static_cast<std::size_t>(raw_file_off)) {
            const auto off = static_cast<std::size_t>(raw_file_off);
            buf = std::vector<std::uint8_t>(
                ctx.static_bytes().begin() + static_cast<std::ptrdiff_t>(off),
                ctx.static_bytes().begin() + static_cast<std::ptrdiff_t>(off + aligned_bytes));
        }

        if (!buf) {
            static_partial = true;
            return;
        }

        const EndianReader reader(*buf, layout);
        const std::uint64_t all_ones =
            layout.is_64bit() ? 0xFFFF'FFFF'FFFF'FFFFull : 0xFFFF'FFFFull;
        const std::size_t count = aligned_bytes / ptr_size;

        for (std::size_t i = 0; i < count; ++i) {
            const std::uint64_t slot_va =
                array_va != 0 ? (array_va + static_cast<std::uint64_t>(i * ptr_size)) : 0u;
            if (slot_va != 0 && emitted_array_slots.contains(slot_va)) {
                continue;
            }

            auto ptr_res = reader.read_pointer(i * ptr_size);
            if (!ptr_res) {
                break;
            }
            std::uint64_t fn_va = *ptr_res;
            if (fn_va == 0 && slot_va != 0 && ctx.session() == nullptr) {
                if (auto rel_target = resolve_elf_static_reloc_slot(*image, slot_va)) {
                    fn_va = *rel_target;
                }
            }
            if (fn_va == 0 || (skip_minus_one_sentinel && fn_va == all_ones)) {
                continue;
            }
            if (fn_va < image->image_base() && ctx.session() != nullptr &&
                !ctx.image_contains_va(*image, fn_va) &&
                ctx.image_contains_va(*image, image->image_base() + fn_va)) {
                fn_va += image->image_base();
            }

            if (slot_va != 0) {
                emitted_array_slots.insert(slot_va);
            }

            HandlerEntry e = make_entry(
                HandlerCategory::ElfInitFini,
                std::string(label) + "[" + std::to_string(i) + "]",
                fn_va,
                ctx.resolve_symbol(fn_va),
                "ELF " + std::string(label) + " function pointer");
            if (slot_va != 0) {
                e.record_address = slot_va;
            }
            if (auto exec = ctx.is_executable_address(fn_va)) {
                e.validated_safe = *exec;
            }
            report.entries.push_back(std::move(e));
        }
    };

    for (const Section& sec : image->sections()) {
        const std::uint64_t span = sec.virtual_size != 0 ? sec.virtual_size : sec.file_size;
        if (span == 0) {
            continue;
        }
        if (sec.name == ".init" || sec.name == ".fini") {
            if (sec.virtual_address != 0 &&
                emitted_single_init_fini.insert(sec.virtual_address).second) {
                HandlerEntry e = make_entry(
                    HandlerCategory::ElfInitFini,
                    sec.name,
                    sec.virtual_address,
                    ctx.resolve_symbol(sec.virtual_address),
                    sec.name == ".init" ? "ELF .init initialization routine"
                                        : "ELF .fini termination routine");
                e.record_address = sec.virtual_address;
                e.scope_start = sec.virtual_address;
                e.scope_end = sec.virtual_address + span;
                report.entries.push_back(std::move(e));
            }
        } else if (sec.name == ".preinit_array" || sec.name.starts_with(".preinit_array.") ||
                   sec.name == ".init_array" || sec.name.starts_with(".init_array.") ||
                   sec.name == ".fini_array" || sec.name.starts_with(".fini_array.")) {
            emit_pointer_array(
                sec.virtual_address, span, sec.file_offset, sec.file_size > 0, sec.name, false);
        } else if (sec.name == ".ctors" || sec.name.starts_with(".ctors.") ||
                   sec.name == ".dtors" || sec.name.starts_with(".dtors.")) {
            emit_pointer_array(
                sec.virtual_address, span, sec.file_offset, sec.file_size > 0, sec.name, true);
        }
    }

    // Check dynamic tags DT_INIT (12), DT_FINI (13), DT_INIT_ARRAY (25)+DT_INIT_ARRAYSZ (27),
    // DT_FINI_ARRAY (26)+DT_FINI_ARRAYSZ (28), DT_PREINIT_ARRAY (32)+DT_PREINIT_ARRAYSZ (33).
    const auto normalize_dyn_va = [&](std::uint64_t raw_va) -> std::uint64_t {
        if (raw_va == 0) {
            return 0;
        }
        if (raw_va < image->image_base() && !ctx.image_contains_va(*image, raw_va) &&
            ctx.image_contains_va(*image, image->image_base() + raw_va)) {
            return image->image_base() + raw_va;
        }
        return raw_va;
    };

    std::uint64_t dt_init = 0;
    std::uint64_t dt_fini = 0;
    std::uint64_t dt_preinit_array = 0;
    std::uint64_t dt_preinit_arraysz = 0;
    std::uint64_t dt_init_array = 0;
    std::uint64_t dt_init_arraysz = 0;
    std::uint64_t dt_fini_array = 0;
    std::uint64_t dt_fini_arraysz = 0;

    for (const ElfDynamicEntry& de : image->elf_dynamic_entries()) {
        switch (de.tag) {
            case 12u: dt_init = normalize_dyn_va(de.value); break;             // DT_INIT
            case 13u: dt_fini = normalize_dyn_va(de.value); break;             // DT_FINI
            case 25u: dt_init_array = normalize_dyn_va(de.value); break;       // DT_INIT_ARRAY
            case 26u: dt_fini_array = normalize_dyn_va(de.value); break;       // DT_FINI_ARRAY
            case 27u: dt_init_arraysz = de.value; break;                       // DT_INIT_ARRAYSZ
            case 28u: dt_fini_arraysz = de.value; break;                       // DT_FINI_ARRAYSZ
            case 32u: dt_preinit_array = normalize_dyn_va(de.value); break;    // DT_PREINIT_ARRAY
            case 33u: dt_preinit_arraysz = de.value; break;                    // DT_PREINIT_ARRAYSZ
            default: break;
        }
    }

    if (dt_init != 0 && emitted_single_init_fini.insert(dt_init).second) {
        HandlerEntry e = make_entry(HandlerCategory::ElfInitFini,
                                    "DT_INIT",
                                    dt_init,
                                    ctx.resolve_symbol(dt_init),
                                    "ELF dynamic DT_INIT initialization function");
        e.record_address = dt_init;
        report.entries.push_back(std::move(e));
    }
    if (dt_fini != 0 && emitted_single_init_fini.insert(dt_fini).second) {
        HandlerEntry e = make_entry(HandlerCategory::ElfInitFini,
                                    "DT_FINI",
                                    dt_fini,
                                    ctx.resolve_symbol(dt_fini),
                                    "ELF dynamic DT_FINI termination function");
        e.record_address = dt_fini;
        report.entries.push_back(std::move(e));
    }
    if (dt_preinit_array != 0 && dt_preinit_arraysz > 0) {
        emit_pointer_array(
            dt_preinit_array, dt_preinit_arraysz, 0, false, "DT_PREINIT_ARRAY", false);
    }
    if (dt_init_array != 0 && dt_init_arraysz > 0) {
        emit_pointer_array(dt_init_array, dt_init_arraysz, 0, false, "DT_INIT_ARRAY", false);
    }
    if (dt_fini_array != 0 && dt_fini_arraysz > 0) {
        emit_pointer_array(dt_fini_array, dt_fini_arraysz, 0, false, "DT_FINI_ARRAY", false);
    }

    // Static ELF exit & signal registration imports/symbols
    struct ElfPlumbingSpec {
        std::string_view sym_name;
        HandlerCategory category;
        std::string_view description;
    };
    static constexpr std::array<ElfPlumbingSpec, 10> kElfPlumbing{{
        {"__cxa_atexit", HandlerCategory::AtexitHandler, "Itanium C++ ABI destructor/atexit registration"},
        {"__cxa_thread_atexit_impl",
         HandlerCategory::AtexitHandler,
         "Thread-local destructor registration"},
        {"atexit", HandlerCategory::AtexitHandler, "POSIX/ISO C exit handler registration"},
        {"on_exit", HandlerCategory::AtexitHandler, "glibc/SunOS on_exit handler registration"},
        {"sigaction",
         HandlerCategory::LinuxSignalDisposition,
         "POSIX sigaction signal handler registration"},
        {"__sigaction",
         HandlerCategory::LinuxSignalDisposition,
         "libc internal sigaction registration"},
        {"__libc_sigaction",
         HandlerCategory::LinuxSignalDisposition,
         "glibc low-level __libc_sigaction"},
        {"signal", HandlerCategory::LinuxSignalDisposition, "ISO C signal handler registration"},
        {"bsd_signal",
         HandlerCategory::LinuxSignalDisposition,
         "BSD signal handler registration"},
        {"__sysv_signal",
         HandlerCategory::LinuxSignalDisposition,
         "SysV signal handler registration"},
    }};

    std::unordered_set<std::string> seen_elf_plumbing;
    for (const ImportEntry& imp : image->imports()) {
        if (imp.name.empty()) {
            continue;
        }
        for (const ElfPlumbingSpec& spec : kElfPlumbing) {
            if (strip_symbol_decorations(imp.name) == spec.sym_name) {
                const std::string key = std::string(spec.sym_name) + ":imp";
                if (!seen_elf_plumbing.insert(key).second) {
                    break;
                }
                HandlerEntry e = make_entry(spec.category,
                                            imp.name,
                                            imp.address,
                                            imp.name,
                                            std::string(spec.description) + " (dynamic import)");
                if (imp.address != 0) {
                    e.record_address = imp.address;
                }
                report.entries.push_back(std::move(e));
                break;
            }
        }
    }
    for (const Symbol& sym : image->symbols()) {
        if (sym.name.empty() || sym.virtual_address == 0) {
            continue;
        }
        for (const ElfPlumbingSpec& spec : kElfPlumbing) {
            if (strip_symbol_decorations(sym.name) == spec.sym_name) {
                const std::string key = std::string(spec.sym_name) + ":sym";
                if (!seen_elf_plumbing.insert(key).second) {
                    break;
                }
                HandlerEntry e = make_entry(spec.category,
                                            sym.name,
                                            sym.virtual_address,
                                            sym.name,
                                            std::string(spec.description) + " (symbol)");
                e.record_address = sym.virtual_address;
                report.entries.push_back(std::move(e));
                break;
            }
        }
    }

    report.static_handlers_status =
        static_partial
            ? SubsystemStatus::partial(
                  "elf-headers", "inspected ELF init/fini arrays with partial byte reads")
            : SubsystemStatus::available(
                  "elf-headers", "inspected ELF init/fini sections, dynamic tags, and symbols");

    // 2. ELF .eh_frame CIE / FDE Personality & LSDA Parser
    EhDecodeBases bases{};
    bases.text_base = image->image_base();
    for (const Section& sec : image->sections()) {
        if (sec.name == ".text" && sec.virtual_address != 0) {
            bases.text_base = sec.virtual_address;
        } else if ((sec.name == ".got.plt" || sec.name == ".got") && sec.virtual_address != 0) {
            if (bases.datarel_base == 0 || sec.name == ".got.plt") {
                bases.datarel_base = sec.virtual_address;
            }
        }
    }

    std::optional<std::uint64_t> eh_frame_va;
    std::uint64_t eh_frame_size = 0;
    std::uint64_t eh_frame_file_off = 0;
    bool eh_has_section = false;

    for (const ElfSectionHeader& sh : image->elf_section_headers()) {
        if (sh.name == ".eh_frame" && sh.size > 0) {
            eh_frame_va = sh.address;
            eh_frame_size = sh.size;
            eh_frame_file_off = sh.offset;
            eh_has_section = true;
            break;
        }
    }
    if (!eh_has_section) {
        for (const Section& sec : image->sections()) {
            if (sec.name == ".eh_frame") {
                const std::uint64_t sz = sec.virtual_size != 0 ? sec.virtual_size : sec.file_size;
                if (sz > 0) {
                    eh_frame_va = sec.virtual_address;
                    eh_frame_size = sz;
                    eh_frame_file_off = sec.file_offset;
                    eh_has_section = true;
                    break;
                }
            }
        }
    }

    // Fallback for section-stripped ELFs: decode PT_GNU_EH_FRAME (.eh_frame_hdr) -> eh_frame_ptr!
    if (!eh_has_section) {
        constexpr std::uint32_t kPtGnuEhFrame = 0x6474'E550u;
        for (const ElfProgramHeader& ph : image->elf_program_headers()) {
            if (ph.type != kPtGnuEhFrame || ph.virtual_address == 0 || ph.memory_size < 8u) {
                continue;
            }
            const auto hdr_sz = static_cast<std::size_t>(std::min<std::uint64_t>(ph.memory_size, 32u));
            auto hdr_bytes = ctx.read_va(ph.virtual_address, hdr_sz);
            if (!hdr_bytes || hdr_bytes->size() < 8u || (*hdr_bytes)[0] != 1u) {
                continue;
            }
            const std::uint8_t eh_ptr_enc = (*hdr_bytes)[1];
            EhDecodeBases hdr_bases = bases;
            hdr_bases.eh_frame_va = ph.virtual_address;
            hdr_bases.datarel_base = ph.virtual_address;
            const EndianReader hr(*hdr_bytes, layout);
            std::size_t cur = 4u;
            if (auto decoded = decode_dw_eh_pe(eh_ptr_enc, hr, cur, hdr_bases, ctx)) {
                if (decoded->address != 0) {
                    eh_frame_va = decoded->address;
                    // Bound by containing PT_LOAD segment up to 4 MiB.
                    for (const Segment& seg : image->segments()) {
                        if (seg.type != 1u) {
                            continue;
                        }
                        const std::uint64_t seg_end =
                            seg.virtual_address + std::max(seg.virtual_size, seg.file_size);
                        if (*eh_frame_va >= seg.virtual_address && *eh_frame_va < seg_end) {
                            eh_frame_size =
                                std::min<std::uint64_t>(seg_end - *eh_frame_va, 4ull * 1024ull * 1024ull);
                            break;
                        }
                    }
                }
            }
            break;
        }
    }

    if (!eh_frame_va.has_value() || eh_frame_size == 0) {
        report.unwind_handlers_status =
            SubsystemStatus::unavailable("elf-eh-frame", ".eh_frame section not present");
        return;
    }

    constexpr std::uint64_t kMaxEhFrameBytes = 16ull * 1024ull * 1024ull;
    const auto read_len =
        static_cast<std::size_t>(std::min<std::uint64_t>(eh_frame_size, kMaxEhFrameBytes));

    std::optional<std::vector<std::uint8_t>> eh_bytes;
    if (*eh_frame_va != 0) {
        eh_bytes = ctx.read_va(*eh_frame_va, read_len);
    } else if (eh_has_section && eh_frame_file_off <= ctx.static_bytes().size() &&
               read_len <= ctx.static_bytes().size() - static_cast<std::size_t>(eh_frame_file_off)) {
        const auto off = static_cast<std::size_t>(eh_frame_file_off);
        eh_bytes = std::vector<std::uint8_t>(
            ctx.static_bytes().begin() + static_cast<std::ptrdiff_t>(off),
            ctx.static_bytes().begin() + static_cast<std::ptrdiff_t>(off + read_len));
    }

    if (!eh_bytes) {
        report.unwind_handlers_status =
            SubsystemStatus::partial("elf-eh-frame", "failed to read .eh_frame bytes");
        return;
    }

    bases.eh_frame_va = *eh_frame_va;
    if (bases.datarel_base == 0) {
        bases.datarel_base = *eh_frame_va;
    }

    struct CieRecord {
        std::uint8_t version{1};
        std::string augmentation;
        bool has_z{false};
        bool has_personality{false};
        bool is_signal_frame{false};
        std::uint8_t personality_encoding{0xFFu};
        std::uint8_t lsda_encoding{0xFFu};
        std::uint8_t fde_encoding{0x00u};
        std::uint64_t personality_va{0};
        std::string personality_symbol;
    };

    const EndianReader eh_reader(*eh_bytes, layout);
    std::unordered_map<std::size_t, CieRecord> cies;
    std::size_t pos = 0;
    std::size_t parsed_cies = 0;
    std::size_t parsed_fdes = 0;
    std::size_t emitted_eh = 0;
    bool eh_truncated = false;
    constexpr std::size_t kMaxEmittedEhEntries = 2048;

    while (pos + 4u <= eh_bytes->size()) {
        const std::size_t record_start = pos;
        const auto len32 = eh_reader.read_u32(pos);
        if (!len32) {
            break;
        }
        pos += 4u;
        if (*len32 == 0) {
            // Terminator record; if section- stripped via PT_GNU_EH_FRAME, stop here.
            if (!eh_has_section) {
                break;
            }
            continue;
        }

        std::uint64_t content_len = *len32;
        const bool dwarf64 = (*len32 == 0xFFFF'FFFFu);
        if (dwarf64) {
            const auto len64 = eh_reader.read_u64(pos);
            if (!len64) {
                eh_truncated = true;
                break;
            }
            pos += 8u;
            content_len = *len64;
        }

        if (content_len < 4u || content_len > eh_bytes->size() - pos) {
            eh_truncated = true;
            break;
        }

        const std::size_t id_pos = pos;
        const std::size_t record_end = pos + static_cast<std::size_t>(content_len);
        const auto cie_id = eh_reader.read_u32(id_pos);
        if (!cie_id) {
            eh_truncated = true;
            break;
        }
        std::size_t cur = id_pos + 4u;

        if (*cie_id == 0) {
            // CIE in .eh_frame
            ++parsed_cies;
            if (cur >= record_end) {
                pos = record_end;
                continue;
            }
            CieRecord cie;
            cie.version = (*eh_bytes)[cur++];

            while (cur < record_end && (*eh_bytes)[cur] != 0) {
                cie.augmentation.push_back(static_cast<char>((*eh_bytes)[cur++]));
            }
            if (cur >= record_end || (*eh_bytes)[cur] != 0) {
                pos = record_end;
                continue;
            }
            ++cur;  // skip NUL

            if (cie.augmentation == "eh") {
                if (ptr_size > record_end - cur) {
                    pos = record_end;
                    continue;
                }
                cur += ptr_size;
            }
            if (cie.version >= 4u) {
                if (record_end - cur < 2u) {
                    pos = record_end;
                    continue;
                }
                cur += 2u;  // address_size + segment_selector_size
            }

            if (!read_uleb128(*eh_bytes, cur) || !read_sleb128(*eh_bytes, cur) || cur > record_end) {
                pos = record_end;
                continue;
            }
            if (cie.version == 1u) {
                if (cur >= record_end) {
                    pos = record_end;
                    continue;
                }
                ++cur;  // ubyte return_address_register
            } else {
                if (!read_uleb128(*eh_bytes, cur) || cur > record_end) {
                    pos = record_end;
                    continue;
                }
            }

            if (!cie.augmentation.empty() && cie.augmentation.front() == 'z') {
                cie.has_z = true;
                const auto aug_len = read_uleb128(*eh_bytes, cur);
                if (!aug_len || *aug_len > record_end - cur) {
                    pos = record_end;
                    continue;
                }
                const std::size_t aug_end = cur + static_cast<std::size_t>(*aug_len);
                for (std::size_t ai = 1; ai < cie.augmentation.size() && cur <= aug_end; ++ai) {
                    const char ch = cie.augmentation[ai];
                    if (ch == 'L') {
                        if (cur >= aug_end) {
                            break;
                        }
                        cie.lsda_encoding = (*eh_bytes)[cur++];
                    } else if (ch == 'P') {
                        if (cur >= aug_end) {
                            break;
                        }
                        cie.personality_encoding = (*eh_bytes)[cur++];
                        if (auto p = decode_dw_eh_pe(
                                cie.personality_encoding, eh_reader, cur, bases, ctx)) {
                            cie.has_personality = (p->address != 0 || !p->symbol_hint.empty());
                            cie.personality_va = p->address;
                            cie.personality_symbol =
                                !p->symbol_hint.empty() ? p->symbol_hint
                                                        : ctx.resolve_symbol(p->address);
                        } else {
                            break;
                        }
                    } else if (ch == 'R') {
                        if (cur >= aug_end) {
                            break;
                        }
                        cie.fde_encoding = (*eh_bytes)[cur++];
                    } else if (ch == 'S') {
                        cie.is_signal_frame = true;
                    } else if (ch == 'B' || ch == 'G') {
                        // AArch64 PAC-RET (B-key) / MTE flags carry no augmentation payload bytes.
                    }
                }
            }

            const std::uint64_t cie_va = *eh_frame_va + static_cast<std::uint64_t>(record_start);
            if ((cie.has_personality || cie.is_signal_frame) &&
                emitted_eh < kMaxEmittedEhEntries) {
                std::string det = "CIE v" + std::to_string(cie.version) + " aug=\"" +
                                  cie.augmentation + "\"";
                if (cie.has_personality) {
                    det += " personality_enc=" + hex_u64(cie.personality_encoding, 2);
                }
                if (cie.is_signal_frame) {
                    det += " (signal trampoline frame)";
                }
                HandlerEntry e = make_entry(
                    HandlerCategory::ElfEhFramePersonality,
                    "CIE@" + hex_u64(cie_va),
                    cie.personality_va,
                    cie.personality_symbol,
                    std::move(det));
                e.record_address = cie_va;
                report.entries.push_back(std::move(e));
                ++emitted_eh;
            }

            cies.emplace(record_start, std::move(cie));
        } else {
            // FDE in .eh_frame: CIE offset is backward from `id_pos`: `id_pos - cie_id`.
            ++parsed_fdes;
            if (static_cast<std::size_t>(*cie_id) <= id_pos) {
                const std::size_t cie_off = id_pos - static_cast<std::size_t>(*cie_id);
                const auto cie_it = cies.find(cie_off);
                if (cie_it != cies.end()) {
                    const CieRecord& cie = cie_it->second;
                    const auto pc_begin =
                        decode_dw_eh_pe(cie.fde_encoding, eh_reader, cur, bases, ctx, false);
                    const auto pc_range = decode_dw_eh_pe(
                        static_cast<std::uint8_t>(cie.fde_encoding & 0x0Fu),
                        eh_reader,
                        cur,
                        bases,
                        ctx,
                        true);
                    if (pc_begin && pc_range && cur <= record_end) {
                        std::uint64_t lsda_va = 0;
                        if (cie.has_z) {
                            if (const auto fde_aug_len = read_uleb128(*eh_bytes, cur)) {
                                if (*fde_aug_len <= record_end - cur &&
                                    cie.lsda_encoding != 0xFFu && *fde_aug_len > 0) {
                                    EhDecodeBases fde_bases = bases;
                                    fde_bases.func_base = pc_begin->address;
                                    if (const auto lsda = decode_dw_eh_pe(cie.lsda_encoding,
                                                                          eh_reader,
                                                                          cur,
                                                                          fde_bases,
                                                                          ctx)) {
                                        lsda_va = lsda->address;
                                    }
                                }
                            }
                        }

                        if ((lsda_va != 0 || cie.has_personality) &&
                            emitted_eh < kMaxEmittedEhEntries &&
                            static_cast<std::uint64_t>(record_start) <=
                                std::numeric_limits<std::uint64_t>::max() - *eh_frame_va) {
                            const std::uint64_t fde_va =
                                *eh_frame_va + static_cast<std::uint64_t>(record_start);
                            const std::uint64_t scope_end =
                                (pc_range->address <=
                                 std::numeric_limits<std::uint64_t>::max() - pc_begin->address)
                                    ? (pc_begin->address + pc_range->address)
                                    : std::numeric_limits<std::uint64_t>::max();
                            const std::string func_sym = ctx.resolve_symbol(pc_begin->address);
                            std::string fde_name =
                                !func_sym.empty() ? ("FDE " + func_sym)
                                                  : ("FDE@" + hex_u64(fde_va));
                            std::string det = "scope=[" + hex_u64(pc_begin->address) + ", " +
                                              hex_u64(scope_end) + ")";
                            if (lsda_va != 0) {
                                det += ", LSDA=" + hex_u64(lsda_va);
                            }
                            if (cie.is_signal_frame) {
                                det += " [signal frame]";
                            }

                            HandlerEntry e = make_entry(
                                HandlerCategory::ElfEhFramePersonality,
                                std::move(fde_name),
                                cie.personality_va,
                                cie.personality_symbol,
                                std::move(det));
                            e.record_address = fde_va;
                            e.scope_start = pc_begin->address;
                            e.scope_end = scope_end;
                            if (lsda_va != 0) {
                                e.lsda_or_data_address = lsda_va;
                            }
                            report.entries.push_back(std::move(e));
                            ++emitted_eh;
                        }
                    }
                }
            }
        }

        pos = record_end;
    }

    const std::string summary =
        "parsed " + std::to_string(parsed_cies) + " CIE(s) and " + std::to_string(parsed_fdes) +
        " FDE(s) (" + std::to_string(emitted_eh) + " personality/LSDA handler entries)";
    if (eh_truncated && parsed_cies == 0 && parsed_fdes == 0) {
        report.unwind_handlers_status =
            SubsystemStatus::partial("elf-eh-frame", "truncated .eh_frame record header");
    } else if (eh_truncated) {
        report.unwind_handlers_status =
            SubsystemStatus::partial("elf-eh-frame", summary + " (truncated tail)");
    } else {
        report.unwind_handlers_status = SubsystemStatus::available("elf-eh-frame", summary);
    }
}

// ---------------------------------------------------------------------------
// Linux Live Signal Dispositions (/proc/<pid>/status SigBlk/SigIgn/SigCgt)
// ---------------------------------------------------------------------------

[[nodiscard]] std::string linux_signal_name(int sig, Architecture arch) {
    const bool mips = (arch == Architecture::MIPS32 || arch == Architecture::MIPS64);
    if (mips) {
        switch (sig) {
            case 7:  return "SIGEMT";
            case 10: return "SIGBUS";
            case 16: return "SIGUSR1";
            case 17: return "SIGUSR2";
            case 18: return "SIGCHLD";
            default: break;
        }
    }
    switch (sig) {
        case 1:  return "SIGHUP";
        case 2:  return "SIGINT";
        case 3:  return "SIGQUIT";
        case 4:  return "SIGILL";
        case 5:  return "SIGTRAP";
        case 6:  return "SIGABRT";
        case 7:  return "SIGBUS";
        case 8:  return "SIGFPE";
        case 9:  return "SIGKILL";
        case 10: return "SIGUSR1";
        case 11: return "SIGSEGV";
        case 12: return "SIGUSR2";
        case 13: return "SIGPIPE";
        case 14: return "SIGALRM";
        case 15: return "SIGTERM";
        case 16: return "SIGSTKFLT";
        case 17: return "SIGCHLD";
        case 18: return "SIGCONT";
        case 19: return "SIGSTOP";
        case 20: return "SIGTSTP";
        case 21: return "SIGTTIN";
        case 22: return "SIGTTOU";
        case 23: return "SIGURG";
        case 24: return "SIGXCPU";
        case 25: return "SIGXFSZ";
        case 26: return "SIGVTALRM";
        case 27: return "SIGPROF";
        case 28: return "SIGWINCH";
        case 29: return "SIGIO";
        case 30: return "SIGPWR";
        case 31: return "SIGSYS";
        case 32: return "SIGRT32";
        case 33: return "SIGRT33";
        default: break;
    }
    if (sig >= 34 && sig <= 64) {
        return "SIGRTMIN+" + std::to_string(sig - 34);
    }
    return "SIG" + std::to_string(sig);
}

[[nodiscard]] bool is_key_linux_signal_name(std::string_view name) noexcept {
    return name == "SIGHUP" || name == "SIGINT" || name == "SIGQUIT" || name == "SIGILL" ||
           name == "SIGTRAP" || name == "SIGABRT" || name == "SIGBUS" || name == "SIGFPE" ||
           name == "SIGSEGV" || name == "SIGPIPE" || name == "SIGALRM" || name == "SIGTERM" ||
           name == "SIGCHLD" || name == "SIGUSR1" || name == "SIGUSR2";
}

void inspect_linux_live_signals(HandlerInspectorContext& ctx, HandlersReport& report) {
    IProcessSession* session = ctx.session();
    if (session == nullptr) {
        report.signal_status =
            SubsystemStatus::unavailable("procfs", "no live process session attached");
        return;
    }

    const ForgivingValue<std::string> proc_status = session->proc_status_text();
    if (!proc_status.has_value() || proc_status.value->empty()) {
        report.signal_status = SubsystemStatus::unavailable(
            proc_status.status.source.empty() ? "procfs" : proc_status.status.source,
            proc_status.status.detail.empty() ? "/proc/<pid>/status text not available"
                                              : proc_status.status.detail);
        return;
    }

    std::optional<std::uint64_t> sig_blk;
    std::optional<std::uint64_t> sig_ign;
    std::optional<std::uint64_t> sig_cgt;

    const std::string_view text = *proc_status.value;
    std::size_t pos = 0;
    while (pos < text.size()) {
        const std::size_t nl = text.find('\n', pos);
        const std::string_view line =
            (nl == std::string_view::npos) ? text.substr(pos) : text.substr(pos, nl - pos);
        pos = (nl == std::string_view::npos) ? text.size() : (nl + 1u);

        const std::size_t colon = line.find(':');
        if (colon == std::string_view::npos) {
            continue;
        }
        const std::string_view key = trim_ascii(line.substr(0, colon));
        const std::string_view val = trim_ascii(line.substr(colon + 1u));
        if (key == "SigBlk") {
            sig_blk = parse_hex_u64(val);
        } else if (key == "SigIgn") {
            sig_ign = parse_hex_u64(val);
        } else if (key == "SigCgt") {
            sig_cgt = parse_hex_u64(val);
        }
    }

    if (!sig_blk && !sig_ign && !sig_cgt) {
        report.signal_status = SubsystemStatus::unavailable(
            "procfs", "SigBlk/SigIgn/SigCgt masks not present in proc status");
        return;
    }

    const std::uint64_t blk_mask = sig_blk.value_or(0);
    const std::uint64_t ign_mask = sig_ign.value_or(0);
    const std::uint64_t cgt_mask = sig_cgt.value_or(0);

    std::size_t caught_count = 0;
    std::size_t ignored_count = 0;

    for (int sig = 1; sig <= 64; ++sig) {
        const std::uint64_t bit = std::uint64_t{1} << static_cast<unsigned int>(sig - 1);
        const bool caught = (cgt_mask & bit) != 0;
        const bool ignored = (ign_mask & bit) != 0;
        const bool blocked = (blk_mask & bit) != 0;
        const std::string name = linux_signal_name(sig, ctx.layout().architecture);

        if (caught) {
            ++caught_count;
        }
        if (ignored) {
            ++ignored_count;
        }

        if (!caught && !ignored && !blocked && !is_key_linux_signal_name(name)) {
            continue;
        }

        SignalDispositionEntry sde;
        sde.signal_number = sig;
        sde.signal_name = name;
        sde.caught = caught;
        sde.ignored = ignored;
        sde.blocked = blocked;
        if (caught) {
            sde.detail = blocked ? "Custom signal handler installed (SigCgt); blocked in SigBlk"
                                 : "Custom signal handler installed (SigCgt)";
        } else if (ignored) {
            sde.detail = blocked ? "Ignored (SIG_IGN); blocked in SigBlk" : "Ignored (SIG_IGN)";
        } else if (blocked) {
            sde.detail = "Default disposition (SIG_DFL); blocked in SigBlk";
        } else {
            sde.detail = "Default disposition (SIG_DFL)";
        }
        report.signals.push_back(std::move(sde));

        if (caught) {
            HandlerEntry he = make_entry(
                HandlerCategory::LinuxSignalDisposition,
                name + " (sig " + std::to_string(sig) + ")",
                0,
                {},
                blocked ? "Caught in /proc/<pid>/status SigCgt (currently blocked in SigBlk)"
                        : "Caught in /proc/<pid>/status SigCgt (user handler address kernel-private)");
            report.entries.push_back(std::move(he));
        }
    }

    const std::string detail =
        "decoded SigBlk/SigIgn/SigCgt (" + std::to_string(caught_count) + " caught, " +
        std::to_string(ignored_count) + " ignored)";
    if (sig_blk && sig_ign && sig_cgt) {
        report.signal_status = SubsystemStatus::available("procfs", detail);
    } else {
        report.signal_status = SubsystemStatus::partial("procfs", detail);
    }
}

// ---------------------------------------------------------------------------
// Live glibc `__exit_funcs` (+ TCB pointer_guard demangling & BSD `__atexit`)
// ---------------------------------------------------------------------------

[[nodiscard]] std::uint64_t glibc_ptr_demangle(std::uint64_t encoded,
                                               std::uint64_t pointer_guard,
                                               const HandlerInspectorContext& ctx) noexcept {
    const TargetLayout layout = ctx.layout();
    if (layout.architecture == Architecture::X86_64) {
        return std::rotr(encoded, 17) ^ pointer_guard;
    }
    if (layout.architecture == Architecture::X86) {
        const auto enc32 = static_cast<std::uint32_t>(encoded & 0xFFFF'FFFFull);
        const auto g32 = static_cast<std::uint32_t>(pointer_guard & 0xFFFF'FFFFull);
        return static_cast<std::uint64_t>(std::rotr(enc32, 9) ^ g32);
    }

    // AArch64 / ARM / RISC-V glibc PTR_DEMANGLE uses plain XOR with __pointer_chk_guard_local;
    // generic C fallback uses rotate-by-(2*sizeof(uintptr_t)+1) then XOR.
    const std::uint64_t plain_xor =
        layout.is_64bit() ? (encoded ^ pointer_guard)
                          : ((encoded ^ pointer_guard) & 0xFFFF'FFFFull);
    const std::uint64_t rot_xor =
        layout.is_64bit()
            ? (std::rotr(encoded, 17) ^ pointer_guard)
            : static_cast<std::uint64_t>(
                  std::rotr(static_cast<std::uint32_t>(encoded & 0xFFFF'FFFFull), 9) ^
                  static_cast<std::uint32_t>(pointer_guard & 0xFFFF'FFFFull));

    const auto plain_exec = ctx.is_executable_address(plain_xor);
    const auto rot_exec = ctx.is_executable_address(rot_xor);
    const bool prefer_plain =
        (layout.architecture == Architecture::ARM || layout.architecture == Architecture::ARM64 ||
         layout.architecture == Architecture::RISCV32 ||
         layout.architecture == Architecture::RISCV64);

    if (prefer_plain) {
        if (plain_exec.has_value() && *plain_exec) {
            return plain_xor;
        }
        if (rot_exec.has_value() && *rot_exec) {
            return rot_xor;
        }
        return plain_xor;
    }

    if (rot_exec.has_value() && *rot_exec) {
        return rot_xor;
    }
    if (plain_exec.has_value() && *plain_exec) {
        return plain_xor;
    }
    return rot_xor;
}

void inspect_live_atexit(HandlerInspectorContext& ctx, Format effective_format, HandlersReport& report) {
    IProcessSession* session = ctx.session();
    if (session == nullptr) {
        report.live_atexit_status =
            SubsystemStatus::unavailable("live", "no live process session attached");
        return;
    }

    const TargetLayout layout = ctx.layout();
    const std::size_t ptr_size = layout.pointer_size();

    struct ExitSymbols {
        std::optional<std::uint64_t> exit_funcs_va;
        std::uint64_t exit_funcs_size{0};
        std::optional<std::uint64_t> pointer_guard_sym_va;
        std::optional<std::uint64_t> bsd_atexit_va;
    };

    const auto scan_for_exit_symbols = [](const IBinaryImage& img, ExitSymbols& out) {
        for (const Symbol& sym : img.symbols()) {
            if (sym.virtual_address == 0 || sym.name.empty()) {
                continue;
            }
            const std::string_view clean = strip_symbol_decorations(sym.name);
            if (!out.exit_funcs_va && clean == "__exit_funcs") {
                out.exit_funcs_va = sym.virtual_address;
                out.exit_funcs_size = sym.size;
            } else if (!out.pointer_guard_sym_va &&
                       (clean == "__pointer_chk_guard" || clean == "__pointer_chk_guard_local")) {
                out.pointer_guard_sym_va = sym.virtual_address;
            } else if (!out.bsd_atexit_va && clean == "__atexit") {
                out.bsd_atexit_va = sym.virtual_address;
            }
        }
        for (const ExportEntry& exp : img.exports()) {
            if (exp.virtual_address == 0 || exp.name.empty()) {
                continue;
            }
            const std::string_view clean = strip_symbol_decorations(exp.name);
            if (!out.exit_funcs_va && clean == "__exit_funcs") {
                out.exit_funcs_va = exp.virtual_address;
            } else if (!out.pointer_guard_sym_va &&
                       (clean == "__pointer_chk_guard" || clean == "__pointer_chk_guard_local")) {
                out.pointer_guard_sym_va = exp.virtual_address;
            } else if (!out.bsd_atexit_va && clean == "__atexit") {
                out.bsd_atexit_va = exp.virtual_address;
            }
        }
    };

    ExitSymbols syms;
    if (ctx.image() != nullptr) {
        scan_for_exit_symbols(*ctx.image(), syms);
    }

    for (const ModuleInfo& mod : ctx.modules()) {
        if (syms.exit_funcs_va && syms.pointer_guard_sym_va) {
            break;
        }
        const bool is_libc_or_ld =
            icontains_ascii(mod.name, "libc.") || icontains_ascii(mod.name, "libc-") ||
            mod.name.starts_with("ld-linux") || mod.name.starts_with("ld.so") ||
            icontains_ascii(mod.name, "ld-musl");
        if (!is_libc_or_ld) {
            continue;
        }
        if (const IBinaryImage* mimg = ctx.get_or_load_module_image(mod)) {
            scan_for_exit_symbols(*mimg, syms);
            if (!syms.exit_funcs_va && mimg->format() == Format::ELF) {
                if (const IBinaryImage* dbg = ctx.get_or_load_build_id_debug_image(*mimg)) {
                    scan_for_exit_symbols(*dbg, syms);
                }
            }
        }
    }

    if (!syms.exit_funcs_va && !syms.bsd_atexit_va) {
        if (effective_format == Format::PE) {
            report.live_atexit_status = SubsystemStatus::unavailable(
                "crt-atexit", "private Windows CRT onexit table symbol not loaded");
        } else {
            report.live_atexit_status = SubsystemStatus::unavailable(
                "libc", "glibc __exit_funcs symbol not available (stripped libc or non-glibc)");
        }
        return;
    }

    // Resolve `pointer_guard` from thread TCB ([fs_base + 0x30] on x86_64, [gs_base + 0x18] on x86)
    // or global `__pointer_chk_guard` symbol.
    std::optional<std::uint64_t> pointer_guard;
    std::string guard_source;

    std::optional<std::uint64_t> tls_tp;
    if (const ThreadContext* tc = ctx.selected_thread()) {
        if (tc->tls_pointer.has_value() && *tc->tls_pointer != 0) {
            tls_tp = *tc->tls_pointer;
        }
    }
    if (!tls_tp.has_value()) {
        if (auto threads = session->threads(); threads && !threads->empty()) {
            for (const ThreadInfo& ti : *threads) {
                if (ti.tls_base.has_value() && *ti.tls_base != 0) {
                    tls_tp = *ti.tls_base;
                    break;
                }
            }
            if (!tls_tp.has_value()) {
                const ThreadContext fallback_tc = session->thread_context(threads->front().tid);
                if (fallback_tc.tls_pointer.has_value() && *fallback_tc.tls_pointer != 0) {
                    tls_tp = *fallback_tc.tls_pointer;
                }
            }
        }
    }

    if (tls_tp.has_value() && *tls_tp != 0) {
        if ((layout.architecture == Architecture::X86_64 ||
             layout.architecture == Architecture::Unknown) &&
            layout.is_64bit()) {
            if (auto gb = ctx.read_live_va(*tls_tp + 0x30u, 8u)) {
                const EndianReader gr(*gb, layout);
                if (auto g = gr.read_u64(0)) {
                    pointer_guard = *g;
                    guard_source = "TCB[fs_base+0x30]";
                }
            }
        } else if ((layout.architecture == Architecture::X86 ||
                    layout.architecture == Architecture::Unknown) &&
                   !layout.is_64bit()) {
            if (auto gb = ctx.read_live_va(*tls_tp + 0x18u, 4u)) {
                const EndianReader gr(*gb, layout);
                if (auto g = gr.read_u32(0)) {
                    pointer_guard = static_cast<std::uint64_t>(*g);
                    guard_source = "TCB[gs_base+0x18]";
                }
            }
        }
    }

    if (!pointer_guard.has_value() && syms.pointer_guard_sym_va.has_value()) {
        if (auto gb = ctx.read_live_va(*syms.pointer_guard_sym_va, ptr_size)) {
            const EndianReader gr(*gb, layout);
            if (auto g = gr.read_pointer(0)) {
                pointer_guard = *g;
                guard_source = "__pointer_chk_guard";
            }
        }
    }

    if (syms.exit_funcs_va.has_value()) {
        // In glibc, `struct exit_function_list *__exit_funcs = &initial;` is a pointer variable
        // (size == ptr_size). Also support synthetic mocks that place `exit_function_list` directly
        // at `__exit_funcs`.
        const std::size_t fn_stride = 4u * ptr_size;
        const std::size_t list_hdr_size = 2u * ptr_size;

        const auto looks_like_exit_list = [&](std::uint64_t cand_va) -> bool {
            if (cand_va == 0) {
                return false;
            }
            auto hdr = ctx.read_live_va(cand_va, list_hdr_size);
            if (!hdr) {
                return false;
            }
            const EndianReader r(*hdr, layout);
            const auto idx = r.read_pointer(ptr_size);
            if (!idx || *idx > 32u) {
                return false;
            }
            if (*idx == 0) {
                return true;
            }
            auto fn0 = ctx.read_live_va(cand_va + static_cast<std::uint64_t>(list_hdr_size), ptr_size);
            if (!fn0) {
                return false;
            }
            const EndianReader fr(*fn0, layout);
            const auto flavor = fr.read_signed_pointer(0);
            return flavor && *flavor >= 0 && *flavor <= 4;
        };

        const std::uint64_t sym_va = *syms.exit_funcs_va;
        auto head_probe = ctx.read_live_va(sym_va, list_hdr_size);
        if (!head_probe) {
            auto ptr_probe = ctx.read_live_va(sym_va, ptr_size);
            if (!ptr_probe) {
                report.live_atexit_status = SubsystemStatus::unavailable(
                    "glibc-exit-funcs", "failed to read __exit_funcs from process memory");
                return;
            }
            head_probe = std::move(ptr_probe);
        }

        const EndianReader pr(*head_probe, layout);
        const std::uint64_t w0 = pr.read_pointer(0).value_or(0);
        const std::optional<std::uint64_t> w1 =
            pr.can_read(ptr_size, ptr_size) ? std::optional<std::uint64_t>(pr.read_pointer(ptr_size).value_or(999u))
                                            : std::nullopt;

        std::uint64_t list_va = 0;
        if (syms.exit_funcs_size == ptr_size) {
            list_va = w0;
        } else if (syms.exit_funcs_size >= list_hdr_size + fn_stride) {
            list_va = sym_va;
        } else if (w0 != 0 && looks_like_exit_list(w0) &&
                   (!w1.has_value() || *w1 > 32u || *w1 == 0)) {
            list_va = w0;
        } else if (looks_like_exit_list(sym_va)) {
            list_va = sym_va;
        } else {
            list_va = w0;
        }

        std::unordered_set<std::uint64_t> visited_lists;
        constexpr std::size_t kMaxListNodes = 32;
        std::size_t list_nodes = 0;
        std::size_t emitted_atexit = 0;
        bool any_undecoded = false;

        while (list_va != 0 && list_nodes < kMaxListNodes) {
            if (!visited_lists.insert(list_va).second) {
                break;
            }
            auto hdr_buf = ctx.read_live_va(list_va, list_hdr_size);
            if (!hdr_buf) {
                break;
            }
            const EndianReader lr(*hdr_buf, layout);
            const auto next_va = lr.read_pointer(0);
            const auto idx_val = lr.read_pointer(ptr_size);
            if (!next_va || !idx_val || *idx_val > 32u) {
                break;
            }

            const auto active_count = static_cast<std::size_t>(*idx_val);
            if (active_count > 0) {
                const std::size_t fns_bytes = active_count * fn_stride;
                const std::uint64_t fns_base_va =
                    list_va + static_cast<std::uint64_t>(list_hdr_size);
                auto fns_buf = ctx.read_live_va(fns_base_va, fns_bytes);
                if (!fns_buf) {
                    break;
                }
                const EndianReader fr(*fns_buf, layout);

                // Walk LIFO (`active_count - 1` down to `0`) matching glibc __run_exit_handlers.
                for (std::size_t rev = active_count; rev > 0; --rev) {
                    const std::size_t slot = rev - 1u;
                    const std::size_t off = slot * fn_stride;
                    const auto flavor = fr.read_signed_pointer(off);
                    const auto encoded_fn = fr.read_pointer(off + ptr_size);
                    const auto arg = fr.read_pointer(off + 2u * ptr_size);
                    const auto dso = fr.read_pointer(off + 3u * ptr_size);
                    if (!flavor || !encoded_fn) {
                        continue;
                    }

                    // ef_free = 0, ef_us = 1, ef_on = 2, ef_at = 3, ef_cxa = 4
                    std::string_view flavor_name;
                    switch (*flavor) {
                        case 0:
                        case 1:
                            continue;
                        case 2: flavor_name = "ef_on"; break;
                        case 3: flavor_name = "ef_at"; break;
                        case 4: flavor_name = "ef_cxa"; break;
                        default: continue;
                    }

                    const std::uint64_t entry_va =
                        fns_base_va + static_cast<std::uint64_t>(off);
                    HandlerEntry e;
                    e.category = HandlerCategory::AtexitHandler;
                    e.category_label = std::string(to_string(HandlerCategory::AtexitHandler));
                    e.name = "__exit_funcs[" + std::to_string(list_nodes) + "][" +
                             std::to_string(slot) + "] (" + std::string(flavor_name) + ")";
                    e.record_address = entry_va;
                    e.pointer_encoded = true;

                    if (*flavor == 4 && dso && *dso != 0) {
                        e.lsda_or_data_address = *dso;
                    } else if ((*flavor == 2 || *flavor == 4) && arg && *arg != 0) {
                        e.lsda_or_data_address = *arg;
                    }

                    std::string extra_args;
                    if ((*flavor == 2 || *flavor == 4) && arg) {
                        extra_args += ", arg=" + hex_u64(*arg);
                    }
                    if (*flavor == 4 && dso) {
                        extra_args += ", dso_handle=" + hex_u64(*dso);
                    }

                    if (pointer_guard.has_value()) {
                        const std::uint64_t demangled =
                            glibc_ptr_demangle(*encoded_fn, *pointer_guard, ctx);
                        e.handler_address = demangled;
                        e.pointer_decoded = true;
                        e.symbol_name = ctx.resolve_symbol(demangled);
                        const auto exec = ctx.is_executable_address(demangled);
                        if (exec.has_value()) {
                            e.validated_safe = *exec;
                        }
                        e.detail = "PTR_DEMANGLE(encoded=" + hex_u64(*encoded_fn) + ", " +
                                   guard_source + "=" + hex_u64(*pointer_guard) + ")" +
                                   extra_args +
                                   (e.validated_safe ? "" : " [outside executable memory!]");
                    } else {
                        any_undecoded = true;
                        e.handler_address = *encoded_fn;
                        e.pointer_decoded = false;
                        e.detail = "Encoded=" + hex_u64(*encoded_fn) + extra_args +
                                   " (pointer_guard unavailable; raw mangled pointer)";
                    }

                    report.entries.push_back(std::move(e));
                    ++emitted_atexit;
                }
            }

            ++list_nodes;
            list_va = *next_va;
        }

        if (list_nodes == 0 && w0 != 0) {
            report.live_atexit_status = SubsystemStatus::unavailable(
                "glibc-exit-funcs", "failed to read exit_function_list at " + hex_u64(w0));
        } else if (any_undecoded) {
            report.live_atexit_status = SubsystemStatus::partial(
                "glibc-exit-funcs",
                "walked " + std::to_string(emitted_atexit) +
                    " glibc exit handler(s); pointer_guard unavailable for PTR_DEMANGLE");
        } else {
            report.live_atexit_status = SubsystemStatus::available(
                "glibc-exit-funcs",
                "walked " + std::to_string(list_nodes) + " exit_function_list node(s) (" +
                    std::to_string(emitted_atexit) + " handler(s))");
        }
        return;
    }

    // BSD / Bionic / newlib `struct _atexit { struct _atexit* next; int ind; void (*fns[32])(); }`
    if (syms.bsd_atexit_va.has_value()) {
        auto head_ptr = ctx.read_live_va(*syms.bsd_atexit_va, ptr_size);
        if (!head_ptr) {
            report.live_atexit_status = SubsystemStatus::unavailable(
                "libc-atexit", "failed to read __atexit head pointer");
            return;
        }
        const EndianReader hpr(*head_ptr, layout);
        std::uint64_t curr = hpr.read_pointer(0).value_or(0);
        std::unordered_set<std::uint64_t> visited;
        std::size_t nodes = 0;
        std::size_t count_emitted = 0;
        while (curr != 0 && nodes < 32u && visited.insert(curr).second) {
            auto hdr = ctx.read_live_va(curr, 2u * ptr_size);
            if (!hdr) {
                break;
            }
            const EndianReader nr(*hdr, layout);
            const std::uint64_t next = nr.read_pointer(0).value_or(0);
            const std::int32_t ind = nr.read_i32(ptr_size).value_or(0);
            if (ind < 0 || ind > 32) {
                break;
            }
            const auto cnt = static_cast<std::size_t>(ind);
            if (cnt > 0) {
                const std::uint64_t fns_va = curr + static_cast<std::uint64_t>(2u * ptr_size);
                if (auto fns_buf = ctx.read_live_va(fns_va, cnt * ptr_size)) {
                    const EndianReader fr(*fns_buf, layout);
                    for (std::size_t rev = cnt; rev > 0; --rev) {
                        const std::size_t slot = rev - 1u;
                        const std::uint64_t fn = fr.read_pointer(slot * ptr_size).value_or(0);
                        if (fn == 0) {
                            continue;
                        }
                        HandlerEntry e = make_entry(
                            HandlerCategory::AtexitHandler,
                            "__atexit[" + std::to_string(nodes) + "][" + std::to_string(slot) + "]",
                            fn,
                            ctx.resolve_symbol(fn),
                            "BSD/newlib __atexit table entry");
                        e.record_address = fns_va + static_cast<std::uint64_t>(slot * ptr_size);
                        if (auto exec = ctx.is_executable_address(fn)) {
                            e.validated_safe = *exec;
                        }
                        report.entries.push_back(std::move(e));
                        ++count_emitted;
                    }
                }
            }
            ++nodes;
            curr = next;
        }
        report.live_atexit_status = SubsystemStatus::available(
            "libc-atexit",
            "walked " + std::to_string(count_emitted) + " __atexit handler(s)");
    }
}

}  // namespace

HandlersReport inspect_handlers(
    const IBinaryImage* image,
    std::span<const std::uint8_t> static_or_module_bytes,
    IProcessSession* session,
    std::span<const MemoryRegion> regions,
    std::span<const ModuleInfo> modules,
    const ThreadContext* selected_thread,
    std::function<std::string(std::uint64_t)> symbol_resolver) {
    HandlersReport report;

    std::vector<MemoryRegion> owned_regions;
    if (regions.empty() && session != nullptr) {
        if (auto r = session->memory_regions()) {
            owned_regions = std::move(*r);
            regions = owned_regions;
        }
    }

    std::vector<ModuleInfo> owned_modules;
    if (modules.empty() && session != nullptr) {
        if (auto m = session->modules()) {
            owned_modules = std::move(*m);
            modules = owned_modules;
        }
    }

    std::unique_ptr<IBinaryImage> owned_image;
    if (image == nullptr && !static_or_module_bytes.empty()) {
        if (auto parsed = parse_image(static_or_module_bytes)) {
            owned_image = std::move(*parsed);
            image = owned_image.get();
        }
    }
    if (image == nullptr && session != nullptr && !modules.empty()) {
        const ModuleInfo* main_mod = nullptr;
        for (const ModuleInfo& mod : modules) {
            if (mod.is_main_module) {
                main_mod = &mod;
                break;
            }
        }
        if (main_mod == nullptr) {
            main_mod = &modules.front();
        }
        if (auto loaded = load_live_module_image(*session, *main_mod, regions)) {
            owned_image = std::move(*loaded);
            image = owned_image.get();
        }
    }

    if (image != nullptr) {
        report.layout = TargetLayout::from_image(*image);
    } else if (session != nullptr) {
        report.layout = session->target_layout();
        if (report.layout.architecture == Architecture::Unknown && selected_thread != nullptr &&
            selected_thread->layout.architecture != Architecture::Unknown) {
            report.layout = selected_thread->layout;
        }
    } else if (selected_thread != nullptr) {
        report.layout = selected_thread->layout;
    }

    Format effective_format = Format::Unknown;
    if (image != nullptr) {
        effective_format = image->format();
    } else if (!static_or_module_bytes.empty()) {
        effective_format = detect_format(static_or_module_bytes);
    } else {
        for (const ModuleInfo& mod : modules) {
            if (mod.format != Format::Unknown) {
                effective_format = mod.format;
                break;
            }
        }
        if (effective_format == Format::Unknown && session != nullptr) {
            if (selected_thread != nullptr && selected_thread->teb_address.has_value()) {
                effective_format = Format::PE;
            } else if (session->process_environment_block_address().has_value()) {
                effective_format = Format::PE;
            } else if (session->proc_status_text().has_value()) {
                effective_format = Format::ELF;
            }
        }
    }

    HandlerInspectorContext ctx(image,
                                static_or_module_bytes,
                                session,
                                regions,
                                modules,
                                selected_thread,
                                std::move(symbol_resolver),
                                report.layout);

    PeModuleSafeSehInfo primary_safeseh;

    if (effective_format == Format::PE) {
        inspect_pe_static_and_unwind(ctx, report, primary_safeseh);
        inspect_pe_live_handlers(ctx, primary_safeseh, report);
        inspect_live_atexit(ctx, Format::PE, report);
        if (session == nullptr) {
            report.signal_status =
                SubsystemStatus::unavailable("procfs", "no live process session attached");
        } else {
            // Allow hybrid/Wine/WSL inspection if proc_status_text is exposed, else mark PE N/A.
            const auto ps = session->proc_status_text();
            if (ps.has_value() && !ps.value->empty()) {
                inspect_linux_live_signals(ctx, report);
            } else {
                report.signal_status = SubsystemStatus::unavailable(
                    "signals", "POSIX /proc signal masks do not apply to Windows PE sessions");
            }
        }
    } else if (effective_format == Format::ELF) {
        inspect_elf_static_and_unwind(ctx, report);
        if (session == nullptr) {
            report.live_seh_veh_status =
                SubsystemStatus::unavailable("pe-live", "no live process session attached");
            report.live_atexit_status =
                SubsystemStatus::unavailable("live", "no live process session attached");
            report.signal_status =
                SubsystemStatus::unavailable("procfs", "no live process session attached");
        } else {
            report.live_seh_veh_status = SubsystemStatus::unavailable(
                "pe-live", "Windows SEH/VEH handlers do not apply to ELF processes");
            inspect_linux_live_signals(ctx, report);
            inspect_live_atexit(ctx, Format::ELF, report);
        }
    } else {
        report.static_handlers_status =
            SubsystemStatus::unavailable("image", "no recognized PE or ELF image loaded");
        report.unwind_handlers_status =
            SubsystemStatus::unavailable("image", "no recognized PE or ELF image loaded");
        if (session == nullptr) {
            report.live_seh_veh_status =
                SubsystemStatus::unavailable("live", "no live process session attached");
            report.live_atexit_status =
                SubsystemStatus::unavailable("live", "no live process session attached");
            report.signal_status =
                SubsystemStatus::unavailable("procfs", "no live process session attached");
        } else {
            inspect_pe_live_handlers(ctx, primary_safeseh, report);
            inspect_linux_live_signals(ctx, report);
            inspect_live_atexit(ctx, Format::Unknown, report);
        }
    }

    return report;
}

}  // namespace peelf
