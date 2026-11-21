#include "ui_app.hpp"
#include "decompile/structured_decompiler.hpp"
#include "logger.hpp"
#include "runtime_paths.hpp"
#include <peelf/sha256.hpp>
#include <algorithm>
#include <array>
#include <cctype>
#include <cinttypes>
#include <cstring>
#include <format>
#include <limits>
#include <span>
#include <string_view>
#include <unordered_map>
#include <unordered_set>

namespace viewer {
namespace {
[[nodiscard]] DecompiledUnit make_decompile_message(DecompileStatus status, std::string diagnostic) {
    DecompiledUnit unit;
    unit.status = status;
    unit.provider = "Decompiler";
    unit.diagnostic = std::move(diagnostic);
    return unit;
}

void copy_cstr_buffer(std::span<char> dest, std::string_view src) noexcept {
    if (dest.empty()) {
        return;
    }
    const std::size_t count = std::min(dest.size() - 1, src.size());
    if (count > 0) {
        std::memcpy(dest.data(), src.data(), count);
    }
    dest[count] = '\0';
}

[[nodiscard]] bool icontains_type_filter(std::string_view hay, std::string_view needle) noexcept {
    while (!needle.empty() && (needle.front() == ' ' || needle.front() == '\t')) {
        needle.remove_prefix(1);
    }
    while (!needle.empty() && (needle.back() == ' ' || needle.back() == '\t')) {
        needle.remove_suffix(1);
    }
    if (needle.empty()) {
        return true;
    }
    if (needle.size() > hay.size()) {
        return false;
    }
    for (std::size_t i = 0; i + needle.size() <= hay.size(); ++i) {
        bool ok = true;
        for (std::size_t j = 0; j < needle.size(); ++j) {
            if (std::tolower(static_cast<unsigned char>(hay[i + j])) !=
                std::tolower(static_cast<unsigned char>(needle[j]))) {
                ok = false;
                break;
            }
        }
        if (ok) {
            return true;
        }
    }
    return false;
}

[[nodiscard]] bool is_builtin_c_type_identifier(std::string_view ident) noexcept {
    static constexpr std::string_view kBuiltinTypeIdents[] = {
        "int8_t",     "uint8_t",    "int16_t",   "uint16_t",  "int32_t",
        "uint32_t",   "int64_t",    "uint64_t",  "size_t",    "ssize_t",
        "uintptr_t",  "intptr_t",   "ptrdiff_t", "undefined", "undefined1",
        "undefined2", "undefined4", "undefined8","byte",      "word",
        "dword",      "qword",      "uchar",     "ushort",    "uint",
        "ulong",      "ulonglong",  "longlong",  "BOOL",      "BYTE",
        "WORD",       "DWORD",      "QWORD",     "HANDLE",    "PVOID",
        "LPVOID",     "LPCSTR",     "LPSTR",     "LPCWSTR",   "LPWSTR",
        "NTSTATUS",   "HRESULT",    "ULONG",     "LONG",      "UINT",
        "SIZE_T",     "NULL",
    };
    for (const std::string_view t : kBuiltinTypeIdents) {
        if (ident == t) {
            return true;
        }
    }
    return false;
}

void scan_line_candidate_identifiers(
    std::string_view line,
    bool is_header_line,
    std::string_view enclosing_func_name,
    const std::unordered_map<std::string_view, std::string_view>& renamed_to_original,
    const std::unordered_set<std::string_view>& known_type_names,
    std::vector<std::string>& out,
    std::unordered_set<std::string>& seen) {
    std::string_view trimmed = line;
    while (!trimmed.empty() && (trimmed.front() == ' ' || trimmed.front() == '\t')) {
        trimmed.remove_prefix(1);
    }
    if (trimmed.empty() || trimmed.starts_with('#')) {
        return;
    }

    std::size_t i = 0u;
    while (i < line.size()) {
        const char ch = line[i];
        if (ch == '/' && i + 1u < line.size()) {
            if (line[i + 1u] == '/') {
                break;
            }
            if (line[i + 1u] == '*') {
                const std::size_t end_c = line.find("*/", i + 2u);
                if (end_c == std::string_view::npos) {
                    break;
                }
                i = end_c + 2u;
                continue;
            }
        }
        if (ch == '"' || ch == '\'') {
            const char q = ch;
            ++i;
            while (i < line.size()) {
                if (line[i] == '\\' && i + 1u < line.size()) {
                    i += 2u;
                } else if (line[i] == q) {
                    ++i;
                    break;
                } else {
                    ++i;
                }
            }
            continue;
        }
        if (ch >= '0' && ch <= '9') {
            ++i;
            while (i < line.size() && (detail::is_override_ident_cont(line[i]) || line[i] == '.')) {
                ++i;
            }
            continue;
        }
        if (detail::is_override_ident_start(ch)) {
            const std::size_t start = i++;
            while (i < line.size() && detail::is_override_ident_cont(line[i])) {
                ++i;
            }
            std::string_view ident = line.substr(start, i - start);

            std::size_t back = start;
            while (back > 0u && (line[back - 1u] == ' ' || line[back - 1u] == '\t')) {
                --back;
            }
            if ((back >= 1u && line[back - 1u] == '.') ||
                (back >= 2u && line[back - 2u] == '-' && line[back - 1u] == '>') ||
                (back >= 2u && line[back - 2u] == ':' && line[back - 1u] == ':')) {
                continue;
            }

            std::size_t fwd = i;
            while (fwd < line.size() && (line[fwd] == ' ' || line[fwd] == '\t')) {
                ++fwd;
            }
            if (!is_header_line && fwd < line.size() && (line[fwd] == '(' || line[fwd] == ':')) {
                continue;
            }
            if (is_header_line && fwd < line.size() && line[fwd] == '(') {
                continue;
            }

            if (const auto alias_it = renamed_to_original.find(ident);
                alias_it != renamed_to_original.end()) {
                ident = alias_it->second;
            }

            if (ident == enclosing_func_name ||
                !is_valid_decompiler_c_identifier(ident) ||
                is_builtin_c_type_identifier(ident) ||
                known_type_names.contains(ident) ||
                ident.starts_with("block_") ||
                ident.starts_with("LAB_") ||
                ident.starts_with("sub_")) {
                continue;
            }

            std::string owned(ident);
            if (seen.insert(owned).second) {
                out.push_back(std::move(owned));
            }
            continue;
        }
        ++i;
    }
}

[[nodiscard]] std::vector<std::string> collect_decompiler_variable_candidates(
    const DecompiledUnit& unit,
    std::optional<std::size_t> priority_line_idx,
    std::string_view enclosing_func_name,
    const DecompilerFunctionOverride* fn_ov,
    std::span<const DataTypeRecord> custom_types,
    std::span<const DataTypeRecord> debug_types) {
    std::unordered_map<std::string_view, std::string_view> renamed_to_original;
    if (fn_ov != nullptr) {
        for (const DecompilerVariableOverride& v : fn_ov->variables) {
            if (!v.renamed_to.empty()) {
                renamed_to_original.emplace(v.renamed_to, v.original_name);
            }
        }
    }

    std::unordered_set<std::string_view> known_type_names;
    for (const DataTypeRecord& t : custom_types) {
        known_type_names.insert(t.name);
        for (const std::string& a : t.aliases) {
            known_type_names.insert(a);
        }
    }
    for (const DataTypeRecord& t : debug_types) {
        known_type_names.insert(t.name);
        for (const std::string& a : t.aliases) {
            known_type_names.insert(a);
        }
    }
    for (const DataTypeRecord& t : unit.types) {
        known_type_names.insert(t.name);
    }

    std::vector<std::string> candidates;
    std::unordered_set<std::string> seen;

    if (priority_line_idx.has_value() && *priority_line_idx < unit.lines.size()) {
        scan_line_candidate_identifiers(
            unit.lines[*priority_line_idx].text,
            *priority_line_idx == 0u,
            enclosing_func_name,
            renamed_to_original,
            known_type_names,
            candidates,
            seen);
    }

    if (fn_ov != nullptr) {
        for (const DecompilerVariableOverride& v : fn_ov->variables) {
            if (seen.insert(v.original_name).second) {
                candidates.push_back(v.original_name);
            }
        }
    }

    for (std::size_t idx = 0u; idx < unit.lines.size(); ++idx) {
        if (priority_line_idx.has_value() && idx == *priority_line_idx) {
            continue;
        }
        scan_line_candidate_identifiers(
            unit.lines[idx].text,
            idx == 0u,
            enclosing_func_name,
            renamed_to_original,
            known_type_names,
            candidates,
            seen);
    }

    return candidates;
}

[[nodiscard]] std::vector<std::string> collect_c_type_suggestions(
    std::span<const DataTypeRecord> custom_types,
    std::span<const DataTypeRecord> debug_types,
    std::span<const DataTypeRecord> unit_types,
    std::string_view filter) {
    static constexpr std::string_view kBuiltinTypes[] = {
        "uint8_t",      "uint16_t",     "uint32_t",   "uint64_t",
        "int8_t",       "int16_t",      "int32_t",    "int64_t",
        "size_t",       "ssize_t",      "uintptr_t",  "intptr_t",
        "const char*",  "char*",        "void*",      "const void*",
        "uint8_t*",     "const uint8_t*","uint32_t*", "uint64_t*",
        "bool",         "char",         "void",       "float",
        "double",
    };

    std::vector<std::string> out;
    std::unordered_set<std::string> seen;
    const auto add_candidate = [&](std::string cand) {
        if (cand.empty() || !normalize_decompiler_c_type(cand).has_value()) {
            return;
        }
        if (!icontains_type_filter(cand, filter)) {
            return;
        }
        if (seen.insert(cand).second) {
            out.push_back(std::move(cand));
        }
    };

    for (const std::string_view builtin : kBuiltinTypes) {
        add_candidate(std::string(builtin));
    }

    const auto append_records = [&](std::span<const DataTypeRecord> records) {
        for (const DataTypeRecord& rec : records) {
            if (out.size() >= 64u) {
                break;
            }
            const char* tag_kw = rec.is_enum ? "enum" : (rec.is_union ? "union" : "struct");
            add_candidate(rec.name);
            if (!rec.is_enum) {
                add_candidate(rec.name + "*");
            }
            add_candidate(std::format("{} {}", tag_kw, rec.name));
            if (!rec.is_enum) {
                add_candidate(std::format("{} {}*", tag_kw, rec.name));
            }
            for (const std::string& alias : rec.aliases) {
                add_candidate(alias);
                if (!rec.is_enum) {
                    add_candidate(alias + "*");
                }
            }
        }
    };
    append_records(custom_types);
    append_records(debug_types);
    append_records(unit_types);
    if (out.size() > 48u) {
        out.resize(48u);
    }
    return out;
}
} // namespace

DecompileValidationStamp UiApp::current_decompile_stamp() const {
    std::string identity = model_.content_sha256();
    if (identity.empty()) {
        identity = model_.file_info().path;
    }
    if (model_.is_live_process() && model_.process_session() != nullptr) {
        identity = std::format("pid:{}:{}:{}",
                               model_.process_session()->pid(),
                               model_.active_module_index().value_or(std::numeric_limits<std::size_t>::max()),
                               identity);
    }
    const std::uint64_t snapshot_rev =
        symbol_revision_ ^ (annotations_.revision() * 0x9E3779B97F4A7C15ULL) ^
        (decompiler_overrides_.revision() * 0xBF58476D1CE4E5B9ULL) ^
        (model_.demangle_symbols() ? 0xD3A461E5ULL : 0ULL) ^
        (thumb_mode_ ? 0x517CC1B727220A95ULL : 0ULL);
    return DecompileValidationStamp{
        .target_identity = std::move(identity),
        .file_generation = file_generation_,
        .edit_revision = model_.edit_revision(),
        .snapshot_revision = snapshot_rev,
    };
}

void UiApp::initialize_decompiler() {
    decompiler_directory_ = viewer::current_executable_directory();
    auto settings = discover_decompilers(decompiler_directory_);
    const auto path = decompiler_directory_ / "decompiler.ini";
    if (std::filesystem::exists(path)) {
        auto saved = read_decompiler_settings(path);
        if (saved) settings = *saved;
        else decompiler_settings_status_ = saved.error().message;
    } else if (settings.ghidra_home.empty()) {
        settings.provider = DecompilerProvider::StructuredPseudoC;
    }
    decompiler_provider_ = static_cast<int>(settings.provider);
    decompiler_timeout_ = settings.timeout_seconds;
    copy_cstr_buffer(ghidra_home_, settings.ghidra_home.string());
    copy_cstr_buffer(binary_ninja_home_, settings.binary_ninja_home.string());
    copy_cstr_buffer(decompiler_java_, settings.java.string());
    copy_cstr_buffer(decompiler_python_, settings.python.string());
    copy_cstr_buffer(decompiler_retdec_, settings.retdec.string());
    refresh_binary_ninja_capabilities(false);
}

void UiApp::refresh_binary_ninja_capabilities(bool run_python_probe) {
    DecompilerSettings settings{};
    settings.provider = static_cast<DecompilerProvider>(decompiler_provider_);
    settings.ghidra_home = ghidra_home_;
    settings.binary_ninja_home = binary_ninja_home_;
    settings.java = decompiler_java_;
    settings.python = decompiler_python_;
    settings.retdec = decompiler_retdec_;
    settings.timeout_seconds = std::clamp(decompiler_timeout_, 5, 15);
    if (run_python_probe) {
        BackendRunner runner;
        const auto resources_dir =
            viewer::resolve_viewer_resources_directory(decompiler_directory_);
        binary_ninja_status_ = probe_binary_ninja_capabilities(
            settings,
            resources_dir / "bn_decompile.py",
            runner);
    } else {
        binary_ninja_status_ = discover_binary_ninja(settings);
    }
    if (binary_ninja_home_[0] == '\0' && binary_ninja_status_.install_found) {
        copy_cstr_buffer(binary_ninja_home_, binary_ninja_status_.install_directory.string());
    }
}
void UiApp::clear_decompiler_caches() {
    decompile_cache_.clear();
    clear_ghidra_workspace_cache(default_ghidra_cache_directory());
    decompiler_settings_status_ = "Cleared decompiler result & workspace caches.";
}

void UiApp::request_decompile(bool force_reanalyze) {
    show_decompiler_ = true;
    focus_decompiler_ = true;
    if (!current_selection_.virtual_address) {
        decompile_controller_.reset_for_new_target();
        decompiled_ = make_decompile_message(
            DecompileStatus::NoFunction,
            "Select a mapped function or executable address first");
        return;
    }

    const std::uint64_t selected_va = *current_selection_.virtual_address;
    const auto* image = model_.image();
    DecompileRequest request;
    request.binary_sha256 = model_.content_sha256();
    request.patch_revision = model_.edit_revision();
    request.symbol_revision =
        symbol_revision_ ^ (annotations_.revision() * 0x9E3779B97F4A7C15ULL) ^
        (decompiler_overrides_.revision() * 0xBF58476D1CE4E5B9ULL) ^
        (model_.demangle_symbols() ? 0xD3A461E5ULL : 0ULL);
    request.force_reanalyze = force_reanalyze;
    selected_code_ranges_.clear();
    selected_code_address_.reset();

    DecompilerSettings settings{};
    settings.provider = static_cast<DecompilerProvider>(decompiler_provider_);
    settings.ghidra_home = ghidra_home_;
    settings.binary_ninja_home = binary_ninja_home_;
    settings.java = decompiler_java_;
    settings.python = decompiler_python_;
    settings.retdec = decompiler_retdec_;
    settings.timeout_seconds = decompiler_timeout_;

    std::optional<SymbolRecord> resolved_root;
    std::optional<DecompileCacheKey> resolved_cache_key;

    if (image != nullptr) {
        auto root = containing_function(*image, symbol_index_, selected_va, navigation_graph_root(selected_va));
        if (!root) {
            if (const auto mapped = image->virtual_address_to_file_offset(selected_va)) {
                root = SymbolRecord{
                    .name = std::format("sub_{:X}", selected_va),
                    .virtual_address = selected_va,
                    .file_offset = *mapped,
                    .function = true,
                    .library = {},
                };
            }
        }
        if (!root || !root->virtual_address) {
            decompile_controller_.reset_for_new_target();
            decompiled_ = make_decompile_message(DecompileStatus::NoFunction, "No function selected");
            return;
        }
        SymbolRecord root_for_extent = *root;
        root_for_extent.file_offset = image->virtual_address_to_file_offset(*root->virtual_address);
        const std::size_t analysis_size = model_.analysis_image_size();
        const auto extent = discover_function_extent(*image, symbol_index_, root_for_extent, analysis_size);
        if (!extent) {
            decompile_controller_.reset_for_new_target();
            decompiled_ = make_decompile_message(DecompileStatus::NoFunction, "Selection is not executable");
            return;
        }
        request.address = extent->virtual_address;
        request.architecture = image->architecture();
        request.endianness = image->endianness();
        if (const auto full = discover_function_extent(
                *image, symbol_index_, root_for_extent, analysis_size, std::numeric_limits<std::uint64_t>::max());
            full && (full->source == FunctionExtentSource::Symbol || full->source == FunctionExtentSource::RuntimeMetadata)) {
            request.function_size = full->size;
        }
        for (auto symbol : symbol_index_.records()) {
            symbol.function = symbol_has_code(*image, symbol);
            bool annotated = false;
            if (symbol.virtual_address) {
                if (const auto* note = annotations_.find(*symbol.virtual_address); note && !note->name.empty()) {
                    symbol.name = note->name;
                    symbol.source = SymbolSource::DebugSymbol;
                    annotated = true;
                }
            }
            if (!annotated && model_.demangle_symbols() && !symbol.demangled_name.empty()) {
                symbol.name = symbol.demangled_name;
            }
            request.symbols.push_back(std::move(symbol));
        }
        request.types = debug_types_;
        if (const auto* fn_ov = decompiler_overrides_.find(request.address); fn_ov != nullptr) {
            request.function_override = *fn_ov;
        } else if (root->virtual_address.has_value()) {
            if (const auto* alt_ov = decompiler_overrides_.find(*root->virtual_address);
                alt_ov != nullptr) {
                request.function_override = *alt_ov;
            }
        }
        if (root->virtual_address.has_value()) {
            if (const auto* note = annotations_.find(*root->virtual_address);
                note != nullptr && !note->name.empty()) {
                root->name = note->name;
            }
        }
        resolved_root = root;
        request.thumb = image->architecture() == peelf::Architecture::ARM && thumb_mode_;

        auto bytes = model_.read_virtual_bytes(extent->virtual_address, static_cast<std::size_t>(extent->size));
        if (!bytes) {
            decompile_controller_.reset_for_new_target();
            decompiled_ = make_decompile_message(DecompileStatus::Failed, bytes.error().message);
            return;
        }
        if (model_.is_live_process()) {
            request.binary_sha256 = std::format("{}:livefn:{}",
                                                request.binary_sha256,
                                                peelf::sha256_hex(*bytes));
        }

        const DecompileCacheKey cache_key = make_decompile_cache_key(request, settings);
        if (force_reanalyze) {
            decompile_cache_.invalidate_function(cache_key.binary_sha256, cache_key.function_address);
        } else if (auto cached = decompile_cache_.get(cache_key)) {
            decompile_controller_.reset_for_new_target();
            decompiled_root_ = resolved_root;
            decompile_revision_ = model_.edit_revision();
            decompile_generation_ = file_generation_;
            decompiler_thumb_ = thumb_mode_;
            decompile_annotation_revision_ = annotations_.revision();
            decompile_symbol_revision_ = symbol_revision_;
            decompile_override_revision_ = decompiler_overrides_.revision();
            decompiled_ = std::move(*cached);
            return;
        }

        const GraphByteReader va_reader = [this](std::uint64_t va, std::size_t len)
            -> std::vector<std::uint8_t> {
            auto res = model_.read_virtual_bytes(va, len);
            return res ? std::move(*res) : std::vector<std::uint8_t>{};
        };
        request.fallback_graph = build_function_cfg_call_graph(
            *bytes,
            extent->virtual_address,
            image->architecture(),
            image->endianness(),
            static_cast<std::size_t>(extent->file_offset),
            root->name,
            thumb_mode_,
            true,
            va_reader);
        const auto chosen_provider = static_cast<DecompilerProvider>(decompiler_provider_);
        if (chosen_provider != DecompilerProvider::AnnotatedCode &&
            chosen_provider != DecompilerProvider::StructuredPseudoC) {
            if (model_.is_live_process()) {
                const auto span = model_.analysis_image_bytes();
                request.image_bytes.assign(span.begin(), span.end());
            } else {
                auto snapshot = model_.read_effective_bytes(0, model_.bytes().size());
                if (!snapshot) {
                    decompile_controller_.reset_for_new_target();
                    decompiled_ = make_decompile_message(DecompileStatus::Failed, snapshot.error().message);
                    return;
                }
                request.image_bytes = std::move(*snapshot);
            }
        }
        resolved_cache_key = cache_key;
    } else if (model_.is_live_process()) {
        // Anonymous / JIT executable memory region without a backing module header.
        auto bytes = model_.read_virtual_bytes(selected_va, 4096);
        if (!bytes || bytes->empty()) {
            decompile_controller_.reset_for_new_target();
            decompiled_ = make_decompile_message(DecompileStatus::NoFunction, "Selected live address is not readable");
            return;
        }
        const std::string fn_name = std::format("live_sub_{:X}", selected_va);
        request.binary_sha256 = std::format("{}:livefn:{}",
                                            request.binary_sha256,
                                            peelf::sha256_hex(*bytes));
        request.address = selected_va;
        request.architecture = model_.architecture();
        request.endianness = model_.endianness();
        request.thumb = request.architecture == peelf::Architecture::ARM && thumb_mode_;
        if (const auto* fn_ov = decompiler_overrides_.find(selected_va); fn_ov != nullptr) {
            request.function_override = *fn_ov;
        }
        const auto recs = symbol_index_.records();
        request.symbols.assign(recs.begin(), recs.end());
        request.fallback_graph = build_function_cfg_call_graph(
            *bytes,
            selected_va,
            model_.architecture(),
            model_.endianness(),
            0,
            fn_name,
            thumb_mode_,
            true);
        request.image_bytes = std::move(*bytes);
        resolved_root = SymbolRecord{
            .name = fn_name,
            .virtual_address = selected_va,
            .file_offset = model_.virtual_address_to_offset(selected_va),
            .function = true,
            .library = {},
        };
        const DecompileCacheKey cache_key = make_decompile_cache_key(request, settings);
        if (force_reanalyze) {
            decompile_cache_.invalidate_function(cache_key.binary_sha256, cache_key.function_address);
        } else if (auto cached = decompile_cache_.get(cache_key)) {
            decompile_controller_.reset_for_new_target();
            decompiled_root_ = resolved_root;
            decompile_revision_ = model_.edit_revision();
            decompile_generation_ = file_generation_;
            decompiler_thumb_ = thumb_mode_;
            decompile_annotation_revision_ = annotations_.revision();
            decompile_symbol_revision_ = symbol_revision_;
            decompile_override_revision_ = decompiler_overrides_.revision();
            decompiled_ = std::move(*cached);
            return;
        }
        resolved_cache_key = cache_key;
    } else {
        decompile_controller_.reset_for_new_target();
        decompiled_ = make_decompile_message(DecompileStatus::NoFunction, "Select a mapped function first");
        return;
    }

    DecompileValidationStamp stamp = current_decompile_stamp();
    decompiled_root_ = resolved_root;
    decompile_revision_ = stamp.edit_revision;
    decompile_generation_ = stamp.file_generation;
    decompiler_thumb_ = thumb_mode_;
    decompile_annotation_revision_ = annotations_.revision();
    decompile_symbol_revision_ = symbol_revision_;
    decompile_override_revision_ = decompiler_overrides_.revision();
    decompiled_ = make_decompile_message(DecompileStatus::Ready, "Analyzing selected function...");

    (void)decompile_controller_.submit(DecompileJobSpec{
        .request = std::move(request),
        .settings = std::move(settings),
        .resources_directory = viewer::resolve_viewer_resources_directory(decompiler_directory_),
        .stamp = std::move(stamp),
        .cache_key = std::move(resolved_cache_key),
        .root_symbol = std::move(resolved_root),
    });
}
void UiApp::open_decompiler_rename_modal(std::optional<std::string_view> preferred_original) {
    decomp_modal_error_.clear();
    const std::optional<std::uint64_t> fn_va =
        (decompiled_root_ && decompiled_root_->virtual_address)
            ? decompiled_root_->virtual_address
            : std::nullopt;
    if (!fn_va.has_value()) {
        return;
    }

    const DecompilerFunctionOverride* fn_ov = decompiler_overrides_.find(*fn_va);
    const std::string_view fn_name =
        decompiled_root_ ? std::string_view(decompiled_root_->name) : std::string_view{};
    decomp_modal_candidates_ = collect_decompiler_variable_candidates(
        decompiled_,
        selected_decompiled_line_index_,
        fn_name,
        fn_ov,
        model_.custom_types(),
        debug_types_);

    decomp_modal_target_idx_ = 0;
    if (preferred_original.has_value() && !preferred_original->empty()) {
        bool found = false;
        for (std::size_t i = 0u; i < decomp_modal_candidates_.size(); ++i) {
            if (decomp_modal_candidates_[i] == *preferred_original) {
                decomp_modal_target_idx_ = static_cast<int>(i + 1u);
                found = true;
                break;
            }
        }
        if (!found) {
            decomp_modal_candidates_.insert(
                decomp_modal_candidates_.begin(), std::string(*preferred_original));
            decomp_modal_target_idx_ = 1;
        }
    } else if (!decomp_modal_candidates_.empty()) {
        const bool header_selected =
            selected_decompiled_line_index_.has_value() && *selected_decompiled_line_index_ == 0u;
        if (!header_selected) {
            decomp_modal_target_idx_ = 1;
        } else {
            // Check whether line 0 itself had a parameter candidate.
            std::vector<std::string> line0_only = collect_decompiler_variable_candidates(
                decompiled_,
                std::size_t{0u},
                fn_name,
                nullptr,
                model_.custom_types(),
                debug_types_);
            decomp_modal_target_idx_ = 0;
            (void)line0_only;
        }
    }

    if (decomp_modal_target_idx_ == 0) {
        copy_cstr_buffer(decomp_target_orig_buf_, fn_name);
        const auto* note = annotations_.find(*fn_va);
        copy_cstr_buffer(
            decomp_rename_buf_,
            (note != nullptr && !note->name.empty()) ? std::string_view(note->name) : fn_name);
    } else {
        const std::string& orig =
            decomp_modal_candidates_[static_cast<std::size_t>(decomp_modal_target_idx_ - 1)];
        copy_cstr_buffer(decomp_target_orig_buf_, orig);
        const auto* var_ov = decompiler_overrides_.find_variable(*fn_va, orig);
        copy_cstr_buffer(
            decomp_rename_buf_,
            (var_ov != nullptr && !var_ov->renamed_to.empty())
                ? std::string_view(var_ov->renamed_to)
                : std::string_view(orig));
    }
    open_decomp_rename_popup_ = true;
}

void UiApp::open_decompiler_type_modal(std::optional<std::string_view> preferred_original,
                                       bool force_function_prototype) {
    decomp_modal_error_.clear();
    const std::optional<std::uint64_t> fn_va =
        (decompiled_root_ && decompiled_root_->virtual_address)
            ? decompiled_root_->virtual_address
            : std::nullopt;
    if (!fn_va.has_value()) {
        return;
    }

    const DecompilerFunctionOverride* fn_ov = decompiler_overrides_.find(*fn_va);
    const std::string_view fn_name =
        decompiled_root_ ? std::string_view(decompiled_root_->name) : std::string_view{};
    decomp_modal_candidates_ = collect_decompiler_variable_candidates(
        decompiled_,
        selected_decompiled_line_index_,
        fn_name,
        fn_ov,
        model_.custom_types(),
        debug_types_);

    const bool header_selected =
        selected_decompiled_line_index_.has_value() && *selected_decompiled_line_index_ == 0u;
    if (force_function_prototype ||
        (!preferred_original.has_value() && (header_selected || decomp_modal_candidates_.empty()))) {
        decomp_type_target_is_function_ = true;
        decomp_modal_target_idx_ = 0;
        copy_cstr_buffer(
            decomp_type_buf_,
            fn_ov != nullptr ? std::string_view(fn_ov->return_type) : std::string_view{});
        copy_cstr_buffer(
            decomp_signature_buf_,
            fn_ov != nullptr ? std::string_view(fn_ov->signature_override) : std::string_view{});
    } else {
        decomp_type_target_is_function_ = false;
        decomp_modal_target_idx_ = 1;
        if (preferred_original.has_value() && !preferred_original->empty()) {
            bool found = false;
            for (std::size_t i = 0u; i < decomp_modal_candidates_.size(); ++i) {
                if (decomp_modal_candidates_[i] == *preferred_original) {
                    decomp_modal_target_idx_ = static_cast<int>(i + 1u);
                    found = true;
                    break;
                }
            }
            if (!found) {
                decomp_modal_candidates_.insert(
                    decomp_modal_candidates_.begin(), std::string(*preferred_original));
                decomp_modal_target_idx_ = 1;
            }
        }
        if (!decomp_modal_candidates_.empty()) {
            const std::string& orig =
                decomp_modal_candidates_[static_cast<std::size_t>(decomp_modal_target_idx_ - 1)];
            copy_cstr_buffer(decomp_target_orig_buf_, orig);
            const auto* var_ov = decompiler_overrides_.find_variable(*fn_va, orig);
            copy_cstr_buffer(
                decomp_type_buf_,
                var_ov != nullptr ? std::string_view(var_ov->c_type) : std::string_view{});
        } else {
            decomp_target_orig_buf_[0] = '\0';
            decomp_type_buf_[0] = '\0';
        }
        copy_cstr_buffer(
            decomp_signature_buf_,
            fn_ov != nullptr ? std::string_view(fn_ov->signature_override) : std::string_view{});
    }
    open_decomp_type_popup_ = true;
}

void UiApp::render_decompiler() {
    if (focus_decompiler_) { ImGui::SetNextWindowFocus(); focus_decompiler_ = false; }
    if (!ImGui::Begin("Decompiler",&show_decompiler_)) { ImGui::End(); return; }
    const bool job_busy = decompile_controller_.is_busy();
    ImGui::BeginDisabled(job_busy);
    static constexpr std::array<const char*, 5> kDecompilerProviderItems = {
        "Ghidra",
        "Binary Ninja HLIL",
        "Annotated assembly",
        "Structured Pseudo-C (built-in)",
        "RetDec CLI",
    };
    ImGui::SetNextItemWidth(-1);
    ImGui::Combo("##provider",
                 &decompiler_provider_,
                 kDecompilerProviderItems.data(),
                 static_cast<int>(kDecompilerProviderItems.size()));
    if (ImGui::CollapsingHeader("Backend settings")) {
        if (decompiler_provider_ == 0) {
            ImGui::TextUnformatted("Ghidra installation folder"); ImGui::SetNextItemWidth(-1);
            ImGui::InputText("##ghidra", ghidra_home_, sizeof(ghidra_home_));
            ImGui::TextUnformatted("Java executable (JDK 25 for Ghidra 12.2)"); ImGui::SetNextItemWidth(-1);
            ImGui::InputText("##java", decompiler_java_, sizeof(decompiler_java_));
            ImGui::InputInt("Timeout (seconds)", &decompiler_timeout_);
        } else if (decompiler_provider_ == 1) {
            ImGui::TextUnformatted("Binary Ninja installation folder (optional; auto-detected)");
            ImGui::SetNextItemWidth(-1);
            ImGui::InputTextWithHint(
                "##bn_home",
                "Auto-detected from BN_INSTALL_DIR / lastrun / standard paths",
                binary_ninja_home_,
                sizeof(binary_ninja_home_));
            ImGui::TextUnformatted("Python executable with Binary Ninja API");
            ImGui::SetNextItemWidth(-1);
            ImGui::InputTextWithHint(
                "##python",
                "Python with Binary Ninja API",
                decompiler_python_,
                sizeof(decompiler_python_));
            ImGui::InputInt("Timeout (seconds)", &decompiler_timeout_);
            if (ImGui::Button("Auto-detect")) {
                binary_ninja_home_[0] = '\0';
                refresh_binary_ninja_capabilities(false);
            }
            ImGui::SameLine();
            if (ImGui::Button("Probe capabilities")) {
                refresh_binary_ninja_capabilities(true);
            }
            ImGui::TextWrapped("%s", binary_ninja_status_.status_summary.c_str());
            const std::string_view ed_name = to_string(binary_ninja_status_.edition);
            ImGui::TextDisabled(
                "Edition: %.*s | Version: %s | Python API: %s | Headless: %s | Archs: %zu",
                static_cast<int>(ed_name.size()),
                ed_name.data(),
                binary_ninja_status_.version.empty() ? "—" : binary_ninja_status_.version.c_str(),
                binary_ninja_status_.python_api_available ? "Yes" : "No",
                binary_ninja_status_.headless_supported ? "Supported" : "Unsupported",
                binary_ninja_status_.supported_architectures.size());
            if (const auto* active_img = model_.image(); active_img != nullptr &&
                (binary_ninja_status_.install_found || binary_ninja_status_.python_api_available)) {
                if (const auto compat = check_binary_ninja_headless_support(
                        binary_ninja_status_, active_img->architecture());
                    !compat) {
                    ImGui::TextWrapped("Active target notice: %s", compat.error().message.c_str());
                }
            }
        } else if (decompiler_provider_ == 4) {
            ImGui::TextUnformatted("RetDec CLI executable");
            ImGui::SetNextItemWidth(-1);
            ImGui::InputTextWithHint("##retdec", "retdec-decompiler", decompiler_retdec_, sizeof(decompiler_retdec_));
            ImGui::InputInt("Timeout (seconds)", &decompiler_timeout_);
        }
        if (ImGui::Button("Save settings")) {
            DecompilerSettings settings{};
            settings.provider = static_cast<DecompilerProvider>(decompiler_provider_);
            settings.ghidra_home = ghidra_home_;
            settings.binary_ninja_home = binary_ninja_home_;
            settings.java = decompiler_java_;
            settings.python = decompiler_python_;
            settings.retdec = decompiler_retdec_;
            settings.timeout_seconds = decompiler_timeout_;
            if (decompiler_timeout_ < 10 || decompiler_timeout_ > 3600) decompiler_settings_status_ = "Timeout must be 10 to 3600 seconds.";
            else {
                const auto result = save_decompiler_settings(decompiler_directory_/"decompiler.ini", settings);
                decompiler_settings_status_ = result ? "Settings saved." : result.error().message;
            }
        }
        ImGui::TextWrapped("%s", decompiler_settings_status_.c_str());
    }
    ImGui::EndDisabled();

    const std::optional<std::uint64_t> active_fn_va =
        (decompiled_root_ && decompiled_root_->virtual_address)
            ? decompiled_root_->virtual_address
            : std::nullopt;
    const bool can_edit_overrides =
        !job_busy && active_fn_va.has_value() && decompiled_.status == DecompileStatus::Ready &&
        !decompiled_.lines.empty();

    if (ImGui::Button("Analyze selection (F5)")) request_decompile(false);
    ImGui::SameLine();
    if (ImGui::Button("Re-analyze")) request_decompile(true);
    ImGui::SameLine();
    ImGui::BeginDisabled(job_busy);
    if (ImGui::Button("Clear Cache")) clear_decompiler_caches();
    ImGui::SameLine();
    bool demangle_decompile = model_.demangle_symbols();
    if (ImGui::Checkbox("Demangle", &demangle_decompile)) {
        model_.set_demangle_symbols(demangle_decompile);
        ++symbol_revision_;
    }
    ImGui::EndDisabled();
    ImGui::SameLine();
    ImGui::BeginDisabled(!can_edit_overrides);
    if (ImGui::Button("Rename (N)")) {
        open_decompiler_rename_modal();
    }
    if (ImGui::IsItemHovered(ImGuiHoveredFlags_AllowWhenDisabled)) {
        ImGui::SetTooltip("Rename function or variable on selected line (Shortcut: N)");
    }
    ImGui::SameLine();
    if (ImGui::Button("Set Type (Y)")) {
        open_decompiler_type_modal();
    }
    if (ImGui::IsItemHovered(ImGuiHoveredFlags_AllowWhenDisabled)) {
        ImGui::SetTooltip("Set variable C type or function prototype (Shortcut: Y)");
    }
    ImGui::EndDisabled();
    if (job_busy) {
        ImGui::SameLine();
        if (ImGui::Button("Cancel")) decompile_controller_.cancel_current();
    }
    ImGui::TextWrapped("%s", decompiled_.provider.c_str());
    if (!job_busy && decompiled_.status == DecompileStatus::Ready && !decompiled_.lines.empty()) {
        ImGui::SameLine();
        const std::string_view source_label = to_string(decompiled_.cache_source);
        ImGui::TextDisabled("[%.*s]", static_cast<int>(source_label.size()), source_label.data());
    }
    ImGui::TextWrapped("%s", decompiled_.diagnostic.c_str());
    if (!job_busy && decompiled_.status != DecompileStatus::Ready && decompiler_provider_ != 3) {
        if (ImGui::Button("Decompile with Structured Pseudo-C")) {
            decompiler_provider_ = 3;
            request_decompile();
        }
    }

    if (active_fn_va.has_value()) {
        const DecompilerFunctionOverride* active_ov = decompiler_overrides_.find(*active_fn_va);
        const std::size_t proto_count =
            (active_ov != nullptr &&
             (!active_ov->return_type.empty() || !active_ov->signature_override.empty()))
                ? 1u
                : 0u;
        const std::size_t var_count = active_ov != nullptr ? active_ov->variables.size() : 0u;
        const std::size_t total_ov_count = proto_count + var_count;
        const std::string drawer_label =
            std::format("Local Variables & Overrides ({})###DecompOverridesDrawer", total_ov_count);
        if (ImGui::CollapsingHeader(drawer_label.c_str())) {
            if (total_ov_count == 0u) {
                ImGui::TextDisabled(
                    "No overrides for 0x%" PRIX64 ". Select a line and press N to rename or Y to set C type / prototype.",
                    *active_fn_va);
            } else {
                bool refresh_after_drawer_action = false;
                if (ImGui::SmallButton("Reset All Overrides")) {
                    if (decompiler_overrides_.clear_function(*active_fn_va)) {
                        refresh_after_drawer_action = true;
                    }
                }
                if (active_ov != nullptr &&
                    (!active_ov->return_type.empty() || !active_ov->signature_override.empty())) {
                    ImGui::SameLine();
                    ImGui::TextDisabled("| Prototype:");
                    ImGui::SameLine();
                    ImGui::Text(
                        "%s%s%s",
                        active_ov->return_type.empty() ? "(default ret)" : active_ov->return_type.c_str(),
                        active_ov->signature_override.empty() ? "" : " ",
                        active_ov->signature_override.c_str());
                    ImGui::SameLine();
                    if (ImGui::SmallButton("Edit##ProtoOv")) {
                        open_decompiler_type_modal(std::nullopt, true);
                    }
                    ImGui::SameLine();
                    if (ImGui::SmallButton("Reset##ProtoOv")) {
                        (void)decompiler_overrides_.set_function_prototype(*active_fn_va, "", "");
                        refresh_after_drawer_action = true;
                    }
                }
                if (active_ov != nullptr && !active_ov->variables.empty()) {
                    const std::vector<DecompilerVariableOverride> vars_snapshot =
                        active_ov->variables;
                    if (ImGui::BeginTable(
                            "decomp_overrides_table",
                            4,
                            ImGuiTableFlags_RowBg | ImGuiTableFlags_BordersInnerV |
                                ImGuiTableFlags_SizingStretchProp)) {
                        ImGui::TableSetupColumn("Original", ImGuiTableColumnFlags_WidthStretch, 1.0f);
                        ImGui::TableSetupColumn("Renamed To", ImGuiTableColumnFlags_WidthStretch, 1.0f);
                        ImGui::TableSetupColumn("C Type", ImGuiTableColumnFlags_WidthStretch, 1.2f);
                        ImGui::TableSetupColumn("Actions", ImGuiTableColumnFlags_WidthFixed, 140.0f);
                        ImGui::TableHeadersRow();
                        for (std::size_t vi = 0u; vi < vars_snapshot.size(); ++vi) {
                            const auto& v = vars_snapshot[vi];
                            ImGui::PushID(static_cast<int>(vi));
                            ImGui::TableNextRow();
                            ImGui::TableSetColumnIndex(0);
                            ImGui::TextUnformatted(v.original_name.c_str());
                            ImGui::TableSetColumnIndex(1);
                            ImGui::TextUnformatted(
                                v.renamed_to.empty() ? "—" : v.renamed_to.c_str());
                            ImGui::TableSetColumnIndex(2);
                            ImGui::TextUnformatted(v.c_type.empty() ? "—" : v.c_type.c_str());
                            ImGui::TableSetColumnIndex(3);
                            if (ImGui::SmallButton("Edit")) {
                                if (!v.renamed_to.empty() || v.c_type.empty()) {
                                    open_decompiler_rename_modal(v.original_name);
                                } else {
                                    open_decompiler_type_modal(v.original_name, false);
                                }
                            }
                            ImGui::SameLine();
                            if (ImGui::SmallButton("Type")) {
                                open_decompiler_type_modal(v.original_name, false);
                            }
                            ImGui::SameLine();
                            if (ImGui::SmallButton("Reset")) {
                                if (decompiler_overrides_.remove_variable(
                                        *active_fn_va, v.original_name)) {
                                    refresh_after_drawer_action = true;
                                }
                            }
                            ImGui::PopID();
                        }
                        ImGui::EndTable();
                    }
                }
                if (refresh_after_drawer_action && !job_busy) {
                    request_decompile(false);
                }
            }
        }
    }

    const bool stale = decompile_revision_ != model_.edit_revision() || decompiler_thumb_ != thumb_mode_ ||
        decompile_annotation_revision_ != annotations_.revision() ||
        decompile_symbol_revision_ != symbol_revision_ ||
        decompile_override_revision_ != decompiler_overrides_.revision();
    if (stale) ImGui::TextWrapped("Bytes or symbols changed. Analyze again to refresh this snapshot.");

    const bool any_decomp_popup_open =
        ImGui::IsPopupOpen("DecompRenamePopup") || ImGui::IsPopupOpen("DecompTypePopup");
    if (ImGui::IsWindowFocused(ImGuiFocusedFlags_RootAndChildWindows) &&
        !ImGui::GetIO().WantTextInput && !any_decomp_popup_open) {
        const ImGuiIO& io = ImGui::GetIO();
        const bool no_mods = !io.KeyCtrl && !io.KeySuper && !io.KeyAlt;
        if (no_mods && can_edit_overrides && ImGui::IsKeyPressed(ImGuiKey_N)) {
            open_decompiler_rename_modal();
        } else if (no_mods && can_edit_overrides && ImGui::IsKeyPressed(ImGuiKey_Y)) {
            open_decompiler_type_modal();
        } else if (no_mods && !job_busy && ImGui::IsKeyPressed(ImGuiKey_F5)) {
            request_decompile(false);
        }
    }

    std::optional<std::size_t> navigate;
    if (code_font_) ImGui::PushFont(code_font_);
    if (ImGui::BeginTable("decompiled_lines",2,ImGuiTableFlags_ScrollY|ImGuiTableFlags_ScrollX|ImGuiTableFlags_RowBg|ImGuiTableFlags_BordersInnerV|ImGuiTableFlags_Resizable)) {
        ImGui::TableSetupColumn("Address",ImGuiTableColumnFlags_WidthFixed,ImGui::CalcTextSize("0000000000000000").x+16);
        ImGui::TableSetupColumn("Code",ImGuiTableColumnFlags_WidthFixed,ImGui::GetFontSize()*80);
        ImGui::TableSetupScrollFreeze(1,1); ImGui::TableHeadersRow();
        ImGuiListClipper clipper; clipper.Begin(static_cast<int>(decompiled_.lines.size()));
        while (clipper.Step()) for(int i=clipper.DisplayStart;i<clipper.DisplayEnd;++i) {
            const auto row_idx = static_cast<std::size_t>(i);
            const auto& line=decompiled_.lines[row_idx]; ImGui::PushID(i);
            ImGui::TableNextRow(); ImGui::TableSetColumnIndex(0);
            bool selected = selected_decompiled_line_index_.has_value() &&
                            *selected_decompiled_line_index_ == row_idx;
            if (line.address) {
                if (current_selection_.virtual_address == line.address) selected = true;
                for (const auto& range : line.ranges) {
                    if (current_selection_.virtual_address &&
                        *current_selection_.virtual_address >= range.address &&
                        *current_selection_.virtual_address - range.address < range.size) {
                        selected = true;
                    }
                }
            }
            const std::string addr_label =
                line.address ? std::format("{:016X}", *line.address) : std::string("—");
            if (ImGui::Selectable(addr_label.c_str(), selected, ImGuiSelectableFlags_SpanAllColumns)) {
                selected_decompiled_line_index_ = row_idx;
                if (line.address && !stale) {
                    navigate = row_idx;
                }
            }
            if (line.address && ImGui::IsItemHovered()) {
                if (const SourceLineMapping* src = model_.find_source_line(*line.address, 32)) {
                    ImGui::SetTooltip("Source: %s:%u", src->file_path.c_str(), src->line);
                }
            }
            if (ImGui::BeginPopupContextItem("DecompLineCtx")) {
                selected_decompiled_line_index_ = row_idx;
                if (ImGui::MenuItem("Rename Function / Variable... (N)", nullptr, false, can_edit_overrides)) {
                    open_decompiler_rename_modal();
                }
                if (ImGui::MenuItem("Set C Type / Prototype... (Y)", nullptr, false, can_edit_overrides)) {
                    open_decompiler_type_modal();
                }
                ImGui::Separator();
                if (ImGui::MenuItem("Copy Line")) {
                    ImGui::SetClipboardText(line.text.c_str());
                }
                if (line.address.has_value() && ImGui::MenuItem("Go to Disassembly")) {
                    (void)navigate_to_address(*line.address, PreferredView::Disassembly);
                }
                ImGui::EndPopup();
            }
            ImGui::TableSetColumnIndex(1); ImGui::TextUnformatted(line.text.c_str());
            ImGui::PopID();
        }
        ImGui::EndTable();
    }
    if (code_font_) ImGui::PopFont();

    if (open_decomp_rename_popup_) {
        ImGui::OpenPopup("DecompRenamePopup");
        open_decomp_rename_popup_ = false;
    }
    if (ImGui::BeginPopup("DecompRenamePopup")) {
        ImGui::TextUnformatted("Rename Function / Variable (N)");
        ImGui::Separator();
        if (active_fn_va.has_value()) {
            const std::string fn_disp = std::format(
                "Function: {} (0x{:X})",
                decompiled_root_ ? decompiled_root_->name : std::string("sub"),
                *active_fn_va);
            const DecompilerFunctionOverride* cur_ov = decompiler_overrides_.find(*active_fn_va);

            const auto preview_label_for = [&](int idx) -> std::string {
                if (idx <= 0 || static_cast<std::size_t>(idx - 1) >= decomp_modal_candidates_.size()) {
                    return std::string{fn_disp};
                }
                const std::string& orig = decomp_modal_candidates_[static_cast<std::size_t>(idx - 1)];
                const auto* vov =
                    cur_ov != nullptr ? decompiler_overrides_.find_variable(*active_fn_va, orig) : nullptr;
                if (vov != nullptr && !vov->renamed_to.empty()) {
                    return std::format("Variable: {} (currently {})", orig, vov->renamed_to);
                }
                return std::format("Variable: {}", orig);
            };

            const std::string current_preview = preview_label_for(decomp_modal_target_idx_);
            ImGui::TextUnformatted("Target:");
            ImGui::SetNextItemWidth(ImGui::GetFontSize() * 26.0f);
            if (ImGui::BeginCombo("##DecompRenameTarget", current_preview.c_str())) {
                if (ImGui::Selectable(fn_disp.c_str(), decomp_modal_target_idx_ == 0)) {
                    decomp_modal_target_idx_ = 0;
                    const auto* note = annotations_.find(*active_fn_va);
                    copy_cstr_buffer(
                        decomp_rename_buf_,
                        (note != nullptr && !note->name.empty())
                            ? std::string_view(note->name)
                            : (decompiled_root_ ? std::string_view(decompiled_root_->name)
                                                : std::string_view{}));
                    decomp_modal_error_.clear();
                }
                for (std::size_t ci = 0u; ci < decomp_modal_candidates_.size(); ++ci) {
                    const int item_idx = static_cast<int>(ci + 1u);
                    const std::string lbl = preview_label_for(item_idx);
                    if (ImGui::Selectable(lbl.c_str(), decomp_modal_target_idx_ == item_idx)) {
                        decomp_modal_target_idx_ = item_idx;
                        const std::string& orig = decomp_modal_candidates_[ci];
                        copy_cstr_buffer(decomp_target_orig_buf_, orig);
                        const auto* vov = decompiler_overrides_.find_variable(*active_fn_va, orig);
                        copy_cstr_buffer(
                            decomp_rename_buf_,
                            (vov != nullptr && !vov->renamed_to.empty())
                                ? std::string_view(vov->renamed_to)
                                : std::string_view(orig));
                        decomp_modal_error_.clear();
                    }
                }
                ImGui::EndCombo();
            }

            if (decomp_modal_target_idx_ > 0) {
                ImGui::TextUnformatted("Original variable / parameter:");
                ImGui::SetNextItemWidth(ImGui::GetFontSize() * 26.0f);
                ImGui::InputTextWithHint(
                    "##DecompOrigVar",
                    "e.g. stack_var_10, rcx, local_18, param_1",
                    decomp_target_orig_buf_,
                    sizeof(decomp_target_orig_buf_));
            }

            ImGui::TextUnformatted("New C identifier:");
            if (ImGui::IsWindowAppearing()) {
                ImGui::SetKeyboardFocusHere();
            }
            ImGui::SetNextItemWidth(ImGui::GetFontSize() * 26.0f);
            const bool submitted = ImGui::InputTextWithHint(
                "##DecompNewIdent",
                decomp_modal_target_idx_ == 0
                    ? "Function name (leave empty to clear user label)"
                    : "Valid C identifier (leave empty to reset rename)",
                decomp_rename_buf_,
                sizeof(decomp_rename_buf_),
                ImGuiInputTextFlags_EnterReturnsTrue);

            if (submitted || ImGui::Button("Apply")) {
                if (decomp_modal_target_idx_ == 0) {
                    const std::string_view trimmed_fn = detail::trim_override_ascii(decomp_rename_buf_);
                    if (!trimmed_fn.empty() && !is_valid_decompiler_c_identifier(trimmed_fn)) {
                        decomp_modal_error_ =
                            "Function label must be a valid C identifier ([A-Za-z_][A-Za-z0-9_]*).";
                    } else {
                        const auto* existing = annotations_.find(*active_fn_va);
                        const std::string keep_comment =
                            existing != nullptr ? existing->comment : std::string{};
                        annotations_.set(*active_fn_va, std::string(trimmed_fn), keep_comment);
                        ++annotation_revision_;
                        ++symbol_revision_;
                        model_.bump_annotation_revision();
                        request_decompile(false);
                        ImGui::CloseCurrentPopup();
                    }
                } else {
                    const auto res = decompiler_overrides_.set_variable_rename(
                        *active_fn_va, decomp_target_orig_buf_, decomp_rename_buf_);
                    if (!res) {
                        decomp_modal_error_ = res.error().message;
                    } else {
                        request_decompile(false);
                        ImGui::CloseCurrentPopup();
                    }
                }
            }
            ImGui::SameLine();
            if (decomp_modal_target_idx_ > 0 && ImGui::Button("Reset Variable")) {
                (void)decompiler_overrides_.set_variable_rename(
                    *active_fn_va, decomp_target_orig_buf_, "");
                request_decompile(false);
                ImGui::CloseCurrentPopup();
            }
            if (decomp_modal_target_idx_ > 0) {
                ImGui::SameLine();
            }
            if (ImGui::Button("Cancel")) {
                ImGui::CloseCurrentPopup();
            }
            if (!decomp_modal_error_.empty()) {
                ImGui::TextColored(
                    ImVec4(0.95f, 0.45f, 0.40f, 1.0f), "%s", decomp_modal_error_.c_str());
            }
        }
        ImGui::EndPopup();
    }

    if (open_decomp_type_popup_) {
        ImGui::OpenPopup("DecompTypePopup");
        open_decomp_type_popup_ = false;
    }
    if (ImGui::BeginPopup("DecompTypePopup")) {
        ImGui::TextUnformatted("Set C Type / Function Prototype (Y)");
        ImGui::Separator();
        if (active_fn_va.has_value()) {
            const DecompilerFunctionOverride* cur_ov = decompiler_overrides_.find(*active_fn_va);
            if (ImGui::RadioButton("Variable / Parameter", !decomp_type_target_is_function_)) {
                decomp_type_target_is_function_ = false;
                if (!decomp_modal_candidates_.empty() && decomp_modal_target_idx_ <= 0) {
                    decomp_modal_target_idx_ = 1;
                    copy_cstr_buffer(decomp_target_orig_buf_, decomp_modal_candidates_[0]);
                }
                const auto* vov = decompiler_overrides_.find_variable(
                    *active_fn_va, decomp_target_orig_buf_);
                copy_cstr_buffer(
                    decomp_type_buf_,
                    vov != nullptr ? std::string_view(vov->c_type) : std::string_view{});
                decomp_modal_error_.clear();
            }
            ImGui::SameLine();
            if (ImGui::RadioButton("Function Return Type / Prototype", decomp_type_target_is_function_)) {
                decomp_type_target_is_function_ = true;
                copy_cstr_buffer(
                    decomp_type_buf_,
                    cur_ov != nullptr ? std::string_view(cur_ov->return_type) : std::string_view{});
                copy_cstr_buffer(
                    decomp_signature_buf_,
                    cur_ov != nullptr ? std::string_view(cur_ov->signature_override)
                                      : std::string_view{});
                decomp_modal_error_.clear();
            }

            if (!decomp_type_target_is_function_) {
                if (!decomp_modal_candidates_.empty()) {
                    const int cur_var_idx = std::clamp(
                        decomp_modal_target_idx_ - 1,
                        0,
                        static_cast<int>(decomp_modal_candidates_.size()) - 1);
                    const std::string& cur_orig =
                        decomp_modal_candidates_[static_cast<std::size_t>(cur_var_idx)];
                    ImGui::TextUnformatted("Select discovered variable:");
                    ImGui::SetNextItemWidth(ImGui::GetFontSize() * 28.0f);
                    if (ImGui::BeginCombo("##DecompTypeVarCombo", cur_orig.c_str())) {
                        for (std::size_t ci = 0u; ci < decomp_modal_candidates_.size(); ++ci) {
                            const std::string& cand = decomp_modal_candidates_[ci];
                            const auto* vov =
                                decompiler_overrides_.find_variable(*active_fn_va, cand);
                            const std::string lbl =
                                (vov != nullptr && !vov->c_type.empty())
                                    ? std::format("{}  [{}]", cand, vov->c_type)
                                    : cand;
                            if (ImGui::Selectable(lbl.c_str(), static_cast<int>(ci) == cur_var_idx)) {
                                decomp_modal_target_idx_ = static_cast<int>(ci + 1u);
                                copy_cstr_buffer(decomp_target_orig_buf_, cand);
                                copy_cstr_buffer(
                                    decomp_type_buf_,
                                    vov != nullptr ? std::string_view(vov->c_type)
                                                   : std::string_view{});
                                decomp_modal_error_.clear();
                            }
                        }
                        ImGui::EndCombo();
                    }
                }
                ImGui::TextUnformatted("Variable identifier:");
                ImGui::SetNextItemWidth(ImGui::GetFontSize() * 28.0f);
                ImGui::InputTextWithHint(
                    "##DecompTypeOrig",
                    "e.g. stack_var_10, rdi, local_18, param_1",
                    decomp_target_orig_buf_,
                    sizeof(decomp_target_orig_buf_));
                ImGui::TextUnformatted("C Type:");
            } else {
                ImGui::Text("Function @ 0x%" PRIX64 " return C type:", *active_fn_va);
            }

            if (ImGui::IsWindowAppearing()) {
                ImGui::SetKeyboardFocusHere();
            }
            ImGui::SetNextItemWidth(ImGui::GetFontSize() * 28.0f);
            bool submitted = ImGui::InputTextWithHint(
                "##DecompCTypeInput",
                "e.g. const char*, size_t, uint32_t, struct PacketHeader*",
                decomp_type_buf_,
                sizeof(decomp_type_buf_),
                ImGuiInputTextFlags_EnterReturnsTrue);

            if (decomp_type_target_is_function_) {
                ImGui::TextUnformatted("Optional custom parameter list or full C prototype:");
                ImGui::SetNextItemWidth(ImGui::GetFontSize() * 28.0f);
                if (ImGui::InputTextWithHint(
                        "##DecompSigInput",
                        "e.g. (const char* buf, size_t len) or int parse(const uint8_t* p, size_t n)",
                        decomp_signature_buf_,
                        sizeof(decomp_signature_buf_),
                        ImGuiInputTextFlags_EnterReturnsTrue)) {
                    submitted = true;
                }
            }

            const std::vector<std::string> suggestions = collect_c_type_suggestions(
                model_.custom_types(),
                debug_types_,
                decompiled_.types,
                decomp_type_buf_);
            if (!suggestions.empty()) {
                ImGui::TextDisabled("Type completions (click to fill):");
                ImGui::BeginChild(
                    "##DecompTypeSuggestions",
                    ImVec2(ImGui::GetFontSize() * 28.0f, ImGui::GetFontSize() * 6.5f),
                    ImGuiChildFlags_Borders);
                for (const std::string& sug : suggestions) {
                    if (ImGui::Selectable(sug.c_str(), sug == decomp_type_buf_)) {
                        copy_cstr_buffer(decomp_type_buf_, sug);
                        decomp_modal_error_.clear();
                    }
                }
                ImGui::EndChild();
            }

            if (submitted || ImGui::Button("Apply")) {
                peelf::Result<void> res{};
                if (decomp_type_target_is_function_) {
                    res = decompiler_overrides_.set_function_prototype(
                        *active_fn_va, decomp_type_buf_, decomp_signature_buf_);
                } else {
                    res = decompiler_overrides_.set_variable_type(
                        *active_fn_va, decomp_target_orig_buf_, decomp_type_buf_);
                }
                if (!res) {
                    decomp_modal_error_ = res.error().message;
                } else {
                    request_decompile(false);
                    ImGui::CloseCurrentPopup();
                }
            }
            ImGui::SameLine();
            if (ImGui::Button("Clear Type")) {
                if (decomp_type_target_is_function_) {
                    (void)decompiler_overrides_.set_function_prototype(*active_fn_va, "", "");
                } else {
                    (void)decompiler_overrides_.set_variable_type(
                        *active_fn_va, decomp_target_orig_buf_, "");
                }
                request_decompile(false);
                ImGui::CloseCurrentPopup();
            }
            ImGui::SameLine();
            if (ImGui::Button("Cancel")) {
                ImGui::CloseCurrentPopup();
            }
            if (!decomp_modal_error_.empty()) {
                ImGui::TextColored(
                    ImVec4(0.95f, 0.45f, 0.40f, 1.0f), "%s", decomp_modal_error_.c_str());
            }
        }
        ImGui::EndPopup();
    }

    ImGui::End();
    if (navigate) select_decompiled_line(*navigate);
}
void UiApp::select_decompiled_line(std::size_t index) {
    const auto& line = decompiled_.lines.at(index);
    if (!line.address || !model_.has_file()) return;
    current_selection_.graph_root = decompiled_root_;
    navigate_to_address(*line.address, model_.image() != nullptr ? PreferredView::Graph : PreferredView::Disassembly);
    if (current_selection_.virtual_address != line.address) return;
    current_selection_.graph_root = decompiled_root_;
    selected_code_ranges_ = line.ranges;
    if (selected_code_ranges_.empty()) {
        auto instruction = std::ranges::find(current_instructions_, *line.address, &Instruction::address);
        selected_code_ranges_.push_back({*line.address, instruction == current_instructions_.end() ? 1 : instruction->bytes.size()});
    }
    std::vector<ByteRange> bytes;
    const std::uint64_t total_view = model_.view_size();
    for (const auto& range : selected_code_ranges_) {
        const auto offset = model_.virtual_address_to_offset(range.address);
        if (!offset || !range.size || *offset >= total_view || range.size > total_view - *offset) continue;
        const auto last = model_.virtual_address_to_offset(range.address + range.size - 1);
        if (!last || *last != *offset + range.size - 1) continue;
        bytes.push_back(ByteRange{*offset, range.size});
    }
    if (!bytes.empty()) {
        hex_panel_.navigate_to_ranges(bytes); hex_panel_.set_visible(true);
        current_selection_.size = bytes.front().size; last_navigation_selection_ = current_selection_;
    }
    selected_code_address_ = line.address;
    if (decompiled_root_ && (!active_graph_root_ || active_graph_root_->virtual_address != decompiled_root_->virtual_address)) {
        pending_call_graph_root_ = decompiled_root_; pending_call_graph_delay_frames_ = 0;
    }
}
void UiApp::render_data_types() {
    if (!ImGui::Begin("Data Structures",&show_data_types_)) { ImGui::End(); return; }
    ImGui::SetNextItemWidth(-1);
    ImGui::InputTextWithHint("##type_search","Search structures, members, types, or data symbols...",data_type_filter_,sizeof(data_type_filter_));
    if (ImGui::BeginTabBar("data_views")) {
        if (ImGui::BeginTabItem("Structures")) {
            if (ImGui::SmallButton("Open Structure View...")) {
                open_structure_view();
            }
            ImGui::SameLine();
            if (ImGui::SmallButton("Define / Import C Types...")) {
                open_structure_view();
                struct_view_panel_.open_custom_c_editor();
            }
            ImGui::SameLine();
            ImGui::TextDisabled("(Built-in PE/ELF/runtime schemas + Custom C + loaded debug types)");
            if (model_.custom_types().empty() && debug_types_.empty() && decompiled_.types.empty())
                ImGui::TextWrapped("No custom C or PDB/DWARF/Ghidra types loaded; built-in PE/ELF/runtime schemas remain available in Structure View.");
            auto draw=[&](const DataTypeRecord& type, std::string_view tag = {}) {
                if (!type_matches(type,data_type_filter_)) return;
                ImGui::PushID(type.name.c_str());
                if (ImGui::SmallButton("Apply")) {
                    if (current_selection_.virtual_address) {
                        open_structure_view(type.name, *current_selection_.virtual_address, false);
                    } else if (current_selection_.file_offset) {
                        open_structure_view(type.name, *current_selection_.file_offset, true);
                    } else {
                        open_structure_view(type.name);
                    }
                }
                if (ImGui::IsItemHovered()) {
                    ImGui::SetTooltip("Apply %s at current selection in Structure View", type.name.c_str());
                }
                ImGui::SameLine();
                const char* kind_kw = type.is_enum ? "enum" : (type.is_union ? "union" : "struct");
                const auto label = tag.empty()
                    ? std::format("{} {} ({} bytes)", kind_kw, type.name, type.size)
                    : std::format("{} {} ({} bytes) [{}]", kind_kw, type.name, type.size, tag);
                if (ImGui::TreeNodeEx("##type",ImGuiTreeNodeFlags_SpanAvailWidth,"%s",label.c_str())) {
                    if (type.is_enum) {
                        if (ImGui::BeginTable("enum_vals",2,ImGuiTableFlags_RowBg|ImGuiTableFlags_BordersInnerV|ImGuiTableFlags_Resizable)) {
                            ImGui::TableSetupColumn("Enumerator");
                            ImGui::TableSetupColumn("Value");
                            ImGui::TableHeadersRow();
                            for (const auto& ec : type.enum_constants) {
                                ImGui::TableNextRow();
                                ImGui::TableSetColumnIndex(0);
                                ImGui::TextUnformatted(ec.name.c_str());
                                ImGui::TableSetColumnIndex(1);
                                if (ec.value < 0) {
                                    ImGui::Text("%" PRId64 " (0x%" PRIX64 ")", ec.value, static_cast<std::uint64_t>(ec.value));
                                } else {
                                    ImGui::Text("0x%" PRIX64 " (%" PRId64 ")", static_cast<std::uint64_t>(ec.value), ec.value);
                                }
                            }
                            ImGui::EndTable();
                        }
                    } else if (ImGui::BeginTable("members",4,ImGuiTableFlags_RowBg|ImGuiTableFlags_BordersInnerV|ImGuiTableFlags_Resizable)) {
                        for (const auto* name : {"Offset","Size","Member","Type"}) ImGui::TableSetupColumn(name);
                        ImGui::TableHeadersRow();
                        for (const auto& member : type.members) {
                            ImGui::TableNextRow();
                            ImGui::TableSetColumnIndex(0);
                            if (member.bit_width > 0) {
                                ImGui::Text("0x%" PRIX64 ".b%u", member.offset, static_cast<unsigned>(member.bit_offset));
                            } else {
                                ImGui::Text("0x%" PRIX64, member.offset);
                            }
                            ImGui::TableSetColumnIndex(1);
                            if (member.bit_width > 0) {
                                ImGui::Text("%u bits", static_cast<unsigned>(member.bit_width));
                            } else {
                                ImGui::Text("%" PRIu64, member.size);
                            }
                            ImGui::TableSetColumnIndex(2); ImGui::TextUnformatted(member.name.c_str());
                            ImGui::TableSetColumnIndex(3); ImGui::TextUnformatted(member.type.c_str());
                        }
                        ImGui::EndTable();
                    }
                    ImGui::TreePop();
                }
                ImGui::PopID();
            };
            const auto custom_span = model_.custom_types();
            for (const auto& type : custom_span) draw(type, "Custom C");
            for (const auto& type : debug_types_)
                if (std::ranges::none_of(custom_span,[&](const auto& known){return known.name==type.name;})) draw(type);
            for (const auto& type : decompiled_.types)
                if (std::ranges::none_of(custom_span,[&](const auto& known){return known.name==type.name;}) &&
                    std::ranges::none_of(debug_types_,[&](const auto& known){return known.name==type.name;})) draw(type);
            ImGui::EndTabItem();
        }
        if (ImGui::BeginTabItem("Data symbols")) {
            struct PendingDataSymNav {
                std::uint64_t va = 0;
                std::optional<std::uint64_t> file_offset;
                std::uint64_t size = 0;
            };
            std::optional<PendingDataSymNav> pending_sym_nav;
            if (model_.image() && ImGui::BeginTable("data_symbols",3,ImGuiTableFlags_RowBg|ImGuiTableFlags_Resizable|ImGuiTableFlags_ScrollY)) {
                ImGui::TableSetupColumn("Name"); ImGui::TableSetupColumn("Address"); ImGui::TableSetupColumn("Size"); ImGui::TableHeadersRow();
                for (const auto& symbol : symbol_index_.records()) {
                    if (!symbol.virtual_address || symbol_has_code(*model_.image(),symbol) || !symbol_name_matches(symbol.name,data_type_filter_)) continue;
                    ImGui::PushID(&symbol); ImGui::TableNextRow(); ImGui::TableSetColumnIndex(0);
                    if (ImGui::Selectable(symbol.name.c_str(),current_selection_.virtual_address==symbol.virtual_address,ImGuiSelectableFlags_SpanAllColumns)) {
                        pending_sym_nav = PendingDataSymNav{*symbol.virtual_address, symbol.file_offset, symbol.size};
                    }
                    ImGui::TableSetColumnIndex(1);
                    ImGui::Text("%016" PRIX64, *symbol.virtual_address);
                    ImGui::TableSetColumnIndex(2);
                    ImGui::Text("%" PRIu64, symbol.size);
                    ImGui::PopID();
                }
                ImGui::EndTable();
            }
            if (pending_sym_nav.has_value()) {
                const PendingDataSymNav nav = *pending_sym_nav;
                pending_navigations_.enqueue_custom([this, nav]() {
                    navigate_to_address(nav.va, PreferredView::Hex);
                    if (nav.file_offset && nav.size) {
                        hex_panel_.navigate_to_range(*nav.file_offset, nav.size);
                    }
                });
            }
            ImGui::EndTabItem();
        }
        ImGui::EndTabBar();
    }
    ImGui::End();
}
}
