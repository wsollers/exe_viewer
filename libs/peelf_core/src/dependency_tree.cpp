#include <peelf/dependency_tree.hpp>

#include <mapping/file_mapping.hpp>

#include <algorithm>
#include <cctype>
#include <cstdlib>
#include <format>
#include <sstream>
#include <unordered_map>
#include <unordered_set>

namespace peelf {

namespace {

[[nodiscard]] std::string to_lower_ascii(std::string_view s) {
    std::string out;
    out.reserve(s.size());
    for (const char ch : s) {
        out.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(ch))));
    }
    return out;
}

[[nodiscard]] std::string_view strip_elf_sym_version(std::string_view name) noexcept {
    const std::size_t at = name.find('@');
    return at == std::string_view::npos ? name : name.substr(0, at);
}

[[nodiscard]] std::string default_elf_lib_token(const IBinaryImage& img) {
    return img.is_64bit() ? "lib64" : "lib";
}

[[nodiscard]] std::string default_elf_platform_token(const IBinaryImage& img) {
    switch (img.architecture()) {
        case Architecture::X86_64:    return "x86_64";
        case Architecture::X86:       return "i686";
        case Architecture::ARM64:     return "aarch64";
        case Architecture::ARM:       return "v7l";
        case Architecture::RISCV64:   return "riscv64";
        case Architecture::RISCV32:   return "riscv32";
        case Architecture::PowerPC64: return img.endianness() == Endianness::Little ? "ppc64le" : "ppc64";
        case Architecture::PowerPC:   return "ppc";
        case Architecture::MIPS64:    return img.endianness() == Endianness::Little ? "mips64el" : "mips64";
        case Architecture::MIPS32:    return img.endianness() == Endianness::Little ? "mipsel" : "mips";
        case Architecture::Unknown:   break;
    }
    return "unknown";
}

[[nodiscard]] std::vector<std::string> elf_multiarch_tuples(const IBinaryImage& img) {
    switch (img.architecture()) {
        case Architecture::X86_64:
            return {"x86_64-linux-gnu"};
        case Architecture::X86:
            return {"i386-linux-gnu", "i686-linux-gnu"};
        case Architecture::ARM64:
            return {"aarch64-linux-gnu"};
        case Architecture::ARM:
            return {"arm-linux-gnueabihf", "arm-linux-gnueabi"};
        case Architecture::RISCV64:
            return {"riscv64-linux-gnu"};
        case Architecture::PowerPC64:
            return img.endianness() == Endianness::Little
                       ? std::vector<std::string>{"powerpc64le-linux-gnu"}
                       : std::vector<std::string>{"powerpc64-linux-gnu"};
        case Architecture::PowerPC:
            return {"powerpc-linux-gnu"};
        case Architecture::MIPS64:
            return img.endianness() == Endianness::Little
                       ? std::vector<std::string>{"mips64el-linux-gnuabi64"}
                       : std::vector<std::string>{"mips64-linux-gnuabi64"};
        case Architecture::MIPS32:
            return img.endianness() == Endianness::Little
                       ? std::vector<std::string>{"mipsel-linux-gnu"}
                       : std::vector<std::string>{"mips-linux-gnu"};
        default:
            return {};
    }
}

void push_unique_string(std::vector<std::string>& vec, std::string val) {
    if (val.empty()) {
        return;
    }
    if (std::ranges::find(vec, val) == vec.end()) {
        vec.push_back(std::move(val));
    }
}

void push_unique_path(std::vector<std::filesystem::path>& vec, const std::filesystem::path& p) {
    if (p.empty()) {
        return;
    }
    if (std::ranges::find(vec, p) == vec.end()) {
        vec.push_back(p);
    }
}

[[nodiscard]] std::vector<std::string> split_colon_list(std::string_view text) {
    std::vector<std::string> parts;
    std::size_t start = 0;
    while (start <= text.size()) {
        const std::size_t sep = text.find(':', start);
        const std::string_view token = sep == std::string_view::npos
                                           ? text.substr(start)
                                           : text.substr(start, sep - start);
        if (!token.empty()) {
            parts.emplace_back(token);
        }
        if (sep == std::string_view::npos) {
            break;
        }
        start = sep + 1;
    }
    return parts;
}

[[nodiscard]] std::string format_image_arch_desc(const IBinaryImage& img) {
    return std::format("{} {}-bit {} {}",
                       to_string(img.format()),
                       img.is_64bit() ? 64 : 32,
                       to_string(img.architecture()),
                       img.endianness() == Endianness::Big ? "BE" : "LE");
}

[[nodiscard]] bool images_compatible(const IBinaryImage& parent, const IBinaryImage& child) noexcept {
    return parent.format() == child.format() &&
           parent.is_64bit() == child.is_64bit() &&
           parent.architecture() == child.architecture() &&
           parent.endianness() == child.endianness();
}

[[nodiscard]] std::filesystem::path normalize_path_key(const std::filesystem::path& p) {
    std::error_code ec;
    const auto canon = std::filesystem::weakly_canonical(p, ec);
    return ec ? p.lexically_normal() : canon;
}

struct ParsedModuleEntry {
    std::unique_ptr<IBinaryImage> image{};
    std::filesystem::path path{};
    std::optional<std::uint64_t> live_base_va{};
    std::string soname{};
    std::vector<std::string> rpaths{};
    std::vector<std::string> runpaths{};
    std::string interpreter{};
};

void extract_elf_dynamic_metadata(const IBinaryImage& img,
                                  std::string& soname_out,
                                  std::vector<std::string>& rpaths_out,
                                  std::vector<std::string>& runpaths_out,
                                  std::string& interp_out) {
    interp_out = std::string(img.elf_interpreter());
    for (const ElfDynamicEntry& de : img.elf_dynamic_entries()) {
        if (de.tag == 14 && !de.string_value.empty()) {  // DT_SONAME
            soname_out = de.string_value;
        } else if (de.tag == 15 && !de.string_value.empty()) {  // DT_RPATH
            for (auto& seg : split_colon_list(de.string_value)) {
                push_unique_string(rpaths_out, std::move(seg));
            }
        } else if (de.tag == 29 && !de.string_value.empty()) {  // DT_RUNPATH
            for (auto& seg : split_colon_list(de.string_value)) {
                push_unique_string(runpaths_out, std::move(seg));
            }
        }
    }
}

struct RequestedSymbolRef {
    std::string name{};
    std::uint32_t ordinal{0};
    bool import_by_ordinal{false};
    bool delay_load{false};
    bool weak_symbol{false};
    std::uint64_t call_site_va{0};
    std::string note{};
};

struct RequestedDependency {
    std::string requested_name{};
    DependencyEdgeKind kind{DependencyEdgeKind::StandardImport};
    std::vector<RequestedSymbolRef> symbols{};
};

[[nodiscard]] std::optional<std::pair<std::string, RequestedSymbolRef>>
parse_pe_forwarder_target(const ExportEntry& exp) {
    if (exp.forwarder.empty()) {
        return std::nullopt;
    }
    const std::size_t dot = exp.forwarder.rfind('.');
    if (dot == std::string::npos || dot == 0 || dot + 1 >= exp.forwarder.size()) {
        return std::nullopt;
    }
    std::string dll = exp.forwarder.substr(0, dot);
    const std::string target = exp.forwarder.substr(dot + 1);
    const std::string lower_dll = to_lower_ascii(dll);
    if (!lower_dll.ends_with(".dll") && !lower_dll.ends_with(".exe") &&
        !lower_dll.ends_with(".drv") && !lower_dll.ends_with(".sys")) {
        dll += ".dll";
    }

    RequestedSymbolRef sym;
    sym.call_site_va = exp.virtual_address;
    sym.note = exp.name.empty()
                   ? std::format("Forwarded from export ordinal #{}", exp.ordinal)
                   : std::format("Forwarded from export {}", exp.name);
    if (target.starts_with('#') && target.size() > 1) {
        char* end_ptr = nullptr;
        const unsigned long ord = std::strtoul(target.c_str() + 1, &end_ptr, 10);
        if (end_ptr != nullptr && *end_ptr == '\0') {
            sym.import_by_ordinal = true;
            sym.ordinal = static_cast<std::uint32_t>(ord);
            sym.name = target;
            return std::make_pair(std::move(dll), std::move(sym));
        }
    }
    sym.name = target;
    return std::make_pair(std::move(dll), std::move(sym));
}

[[nodiscard]] std::vector<RequestedDependency> collect_direct_requests(const IBinaryImage& img) {
    std::vector<RequestedDependency> requests;
    if (img.format() == Format::PE) {
        std::unordered_map<std::string, std::size_t> by_key;
        struct GroupFlags {
            bool any_standard{false};
            bool any_delay{false};
        };
        std::unordered_map<std::size_t, GroupFlags> flags;

        for (const ImportEntry& imp : img.imports()) {
            if (imp.library.empty()) {
                continue;
            }
            const std::string key = "imp:" + to_lower_ascii(imp.library);
            auto [it, inserted] = by_key.emplace(key, requests.size());
            if (inserted) {
                RequestedDependency req;
                req.requested_name = imp.library;
                req.kind = imp.delay_load ? DependencyEdgeKind::DelayLoadImport
                                          : DependencyEdgeKind::StandardImport;
                requests.push_back(std::move(req));
            }
            const std::size_t idx = it->second;
            if (imp.delay_load) {
                flags[idx].any_delay = true;
            } else {
                flags[idx].any_standard = true;
            }

            RequestedSymbolRef sym;
            sym.name = imp.import_by_ordinal && imp.name.empty()
                           ? std::format("#{}", imp.ordinal)
                           : imp.name;
            sym.ordinal = imp.ordinal;
            sym.import_by_ordinal = imp.import_by_ordinal;
            sym.delay_load = imp.delay_load;
            sym.call_site_va = imp.address;
            if (!sym.name.empty() || sym.import_by_ordinal) {
                requests[idx].symbols.push_back(std::move(sym));
            }
        }

        for (const auto& [idx, fl] : flags) {
            requests[idx].kind = (fl.any_delay && !fl.any_standard)
                                     ? DependencyEdgeKind::DelayLoadImport
                                     : DependencyEdgeKind::StandardImport;
        }

        for (const ExportEntry& exp : img.exports()) {
            auto fwd = parse_pe_forwarder_target(exp);
            if (!fwd.has_value()) {
                continue;
            }
            const std::string key = "fwd:" + to_lower_ascii(fwd->first);
            auto [it, inserted] = by_key.emplace(key, requests.size());
            if (inserted) {
                RequestedDependency req;
                req.requested_name = fwd->first;
                req.kind = DependencyEdgeKind::ForwardedExport;
                requests.push_back(std::move(req));
            }
            requests[it->second].symbols.push_back(std::move(fwd->second));
        }
    } else if (img.format() == Format::ELF) {
        std::unordered_set<std::string> seen;
        const std::string_view interp = img.elf_interpreter();
        if (!interp.empty()) {
            seen.emplace(interp);
            RequestedDependency req;
            req.requested_name = std::string(interp);
            req.kind = DependencyEdgeKind::DynamicLinkerInterp;
            requests.push_back(std::move(req));
        }

        for (const ElfDynamicEntry& de : img.elf_dynamic_entries()) {
            if (de.tag != 1) {  // DT_NEEDED
                continue;
            }
            const std::string& lib = !de.needed_library.empty() ? de.needed_library : de.string_value;
            if (!lib.empty() && seen.emplace(lib).second) {
                RequestedDependency req;
                req.requested_name = lib;
                req.kind = DependencyEdgeKind::StandardImport;
                requests.push_back(std::move(req));
            }
        }
        // Fallback if imports() was populated without dynamic_entries_
        for (const ImportEntry& imp : img.imports()) {
            if (!imp.library.empty() && seen.emplace(imp.library).second) {
                RequestedDependency req;
                req.requested_name = imp.library;
                req.kind = DependencyEdgeKind::StandardImport;
                requests.push_back(std::move(req));
            }
        }
    }
    return requests;
}

[[nodiscard]] std::vector<RequestedSymbolRef> collect_elf_undefined_symbols(const IBinaryImage& img) {
    std::unordered_map<std::string, std::uint64_t> reloc_va_by_sym;
    for (const ElfRelocation& rel : img.elf_relocations()) {
        if (!rel.symbol_name.empty() && rel.offset != 0) {
            const std::string base(strip_elf_sym_version(rel.symbol_name));
            reloc_va_by_sym.try_emplace(base, rel.offset);
        }
    }

    std::vector<RequestedSymbolRef> undefs;
    std::unordered_set<std::string> seen;
    for (const ElfSymbol& es : img.elf_symbols()) {
        if (!es.dynamic || es.section_index != 0 || es.name.empty()) {
            continue;
        }
        // STB_GLOBAL (1) or STB_WEAK (2)
        if (es.binding != 1 && es.binding != 2) {
            continue;
        }
        const std::string base(strip_elf_sym_version(es.name));
        if (base.empty() || !seen.emplace(base).second) {
            continue;
        }
        RequestedSymbolRef sym;
        sym.name = base;
        sym.weak_symbol = (es.binding == 2);
        if (auto it = reloc_va_by_sym.find(base); it != reloc_va_by_sym.end()) {
            sym.call_site_va = it->second;
        }
        undefs.push_back(std::move(sym));
    }
    return undefs;
}

[[nodiscard]] std::unordered_map<std::string, std::uint64_t>
build_elf_export_map(const IBinaryImage& child) {
    std::unordered_map<std::string, std::uint64_t> out;
    for (const ElfSymbol& es : child.elf_symbols()) {
        if (!es.dynamic || es.section_index == 0 || es.name.empty()) {
            continue;
        }
        // STB_GLOBAL (1), STB_WEAK (2), STB_GNU_UNIQUE (10)
        if (es.binding != 1 && es.binding != 2 && es.binding != 10) {
            continue;
        }
        const std::string base(strip_elf_sym_version(es.name));
        if (!base.empty()) {
            out.try_emplace(base, es.value);
        }
    }
    for (const ExportEntry& exp : child.exports()) {
        if (!exp.name.empty()) {
            const std::string base(strip_elf_sym_version(exp.name));
            out.try_emplace(base, exp.virtual_address);
        }
    }
    return out;
}

[[nodiscard]] std::optional<std::filesystem::path>
probe_directory_for_file(const std::filesystem::path& dir,
                         std::string_view filename,
                         bool case_insensitive_fallback,
                         std::vector<std::filesystem::path>& searched_out) {
    if (dir.empty()) {
        return std::nullopt;
    }
    std::filesystem::path direct = (dir / filename).lexically_normal();
    push_unique_path(searched_out, direct);
    std::error_code ec;
    if (std::filesystem::is_regular_file(direct, ec)) {
        return direct;
    }
    if (!case_insensitive_fallback || !std::filesystem::is_directory(dir, ec)) {
        return std::nullopt;
    }
    const std::string target_lower = to_lower_ascii(filename);
    for (const auto& entry : std::filesystem::directory_iterator(dir, ec)) {
        if (ec) {
            break;
        }
        std::error_code f_ec;
        if (!entry.is_regular_file(f_ec)) {
            continue;
        }
        const std::string cand_name = entry.path().filename().string();
        if (to_lower_ascii(cand_name) == target_lower) {
            return entry.path().lexically_normal();
        }
    }
    return std::nullopt;
}

class GraphBuilder {
public:
    GraphBuilder(const IBinaryImage& root_image,
                 const DependencyResolveOptions& opts,
                 IProcessSession* live_session)
        : root_image_(root_image), opts_(opts), live_session_(live_session) {
        if (live_session_ != nullptr) {
            if (auto mods = live_session_->modules(); mods.has_value()) {
                live_modules_ = std::move(*mods);
            }
        }
        if (opts_.use_env_ld_library_path) {
            if (const char* env_ld = std::getenv("LD_LIBRARY_PATH"); env_ld != nullptr && *env_ld != '\0') {
                for (auto& p : parse_search_roots_list(env_ld)) {
                    env_ld_paths_.push_back(std::move(p));
                }
            }
        }
    }

    [[nodiscard]] DependencyGraph build() {
        DependencyNode root;
        root.id = 0;
        root.status = DependencyResolutionStatus::RootModule;
        root.format = root_image_.format();
        root.architecture = root_image_.architecture();
        root.endianness = root_image_.endianness();
        root.is_64bit = root_image_.is_64bit();
        root.export_count = root_image_.exports().size();
        root.resolved_path = opts_.root_path;
        root.requested_name = !opts_.root_path.empty()
                                  ? opts_.root_path.filename().string()
                                  : std::format("<root {} image>", to_string(root_image_.format()));
        root.display_name = root.requested_name;
        root.resolution_reason = live_session_ != nullptr
                                     ? "Attached live process root module"
                                     : "Static analysis root binary";
        if (live_session_ != nullptr && root_image_.image_base() != 0) {
            root.live_base_va = root_image_.image_base();
        }
        extract_elf_dynamic_metadata(root_image_,
                                     root.soname,
                                     root.elf_rpaths,
                                     root.elf_runpaths,
                                     root.elf_interpreter);
        if (!root.soname.empty() && opts_.root_path.empty()) {
            root.display_name = root.soname;
        }
        graph_.nodes.push_back(std::move(root));
        if (!opts_.root_path.empty()) {
            const std::string key = "path:" + normalize_path_key(opts_.root_path).generic_string();
            node_id_by_key_.emplace(key, 0);
        }

        graph_.root_tree.node_id = 0;
        graph_.root_tree.requested_name = graph_.nodes[0].display_name;
        graph_.root_tree.status = DependencyResolutionStatus::RootModule;
        graph_.root_tree.depth = 0;

        std::vector<std::size_t> ancestors{0};
        std::vector<std::pair<std::string, std::filesystem::path>> inherited_rpaths;
        const std::filesystem::path root_origin =
            !opts_.root_path.empty() ? opts_.root_path.parent_path() : std::filesystem::path{};
        if (graph_.nodes[0].elf_runpaths.empty()) {
            for (const std::string& rp : graph_.nodes[0].elf_rpaths) {
                inherited_rpaths.emplace_back(rp, root_origin);
            }
        }

        expand_node(0, root_image_, root_origin, inherited_rpaths, 0, ancestors, graph_.root_tree);
        compute_summary();
        return std::move(graph_);
    }

private:
    struct CandidateResult {
        DependencyResolutionStatus status{DependencyResolutionStatus::Unresolved};
        std::filesystem::path path{};
        std::string reason{};
        std::vector<std::filesystem::path> searched_paths{};
        std::vector<std::string> origin_assumptions{};
        const IBinaryImage* parsed_image{nullptr};
        std::optional<std::uint64_t> live_base_va{};
    };

    const ParsedModuleEntry* load_or_get_disk_module(const std::filesystem::path& path) {
        const std::string key = normalize_path_key(path).generic_string();
        if (auto it = parsed_cache_.find(key); it != parsed_cache_.end()) {
            return &it->second;
        }
        FileMapping<std::uint8_t, NativeFileMappingBackend> mapped;
        if (auto ec = mapped.open(path.string(), MapMode::read_only); ec) {
            return nullptr;
        }
        auto parsed = parse_image(mapped.view());
        if (!parsed.has_value() || !*parsed) {
            return nullptr;
        }
        ParsedModuleEntry entry;
        entry.path = path;
        extract_elf_dynamic_metadata(**parsed,
                                     entry.soname,
                                     entry.rpaths,
                                     entry.runpaths,
                                     entry.interpreter);
        for (const ModuleInfo& mod : live_modules_) {
            if (!mod.path.empty() && normalize_path_key(mod.path) == normalize_path_key(path)) {
                entry.live_base_va = mod.base_address;
                break;
            }
        }
        entry.image = std::move(*parsed);
        auto [ins_it, _] = parsed_cache_.emplace(key, std::move(entry));
        return &ins_it->second;
    }

    const ParsedModuleEntry* load_or_get_live_module(const ModuleInfo& mod) {
        if (!mod.path.empty()) {
            std::error_code ec;
            if (std::filesystem::is_regular_file(mod.path, ec)) {
                if (const auto* disk_ent = load_or_get_disk_module(mod.path)) {
                    return disk_ent;
                }
            }
        }
        if (live_session_ == nullptr || mod.base_address == 0) {
            return nullptr;
        }
        const std::string key = std::format("live:{:#x}", mod.base_address);
        if (auto it = parsed_cache_.find(key); it != parsed_cache_.end()) {
            return &it->second;
        }
        auto live_img = load_live_module_image(*live_session_, mod);
        if (!live_img.has_value() || !*live_img) {
            return nullptr;
        }
        ParsedModuleEntry entry;
        entry.path = mod.path;
        entry.live_base_va = mod.base_address;
        extract_elf_dynamic_metadata(**live_img,
                                     entry.soname,
                                     entry.rpaths,
                                     entry.runpaths,
                                     entry.interpreter);
        entry.image = std::move(*live_img);
        auto [ins_it, _] = parsed_cache_.emplace(key, std::move(entry));
        return &ins_it->second;
    }

    [[nodiscard]] const ModuleInfo* find_matching_live_module(std::string_view requested_name,
                                                              bool case_insensitive) const {
        const std::filesystem::path req_p(requested_name);
        const std::string req_fname = req_p.filename().string();
        const std::string req_lower = to_lower_ascii(req_fname);

        for (const ModuleInfo& mod : live_modules_) {
            const std::string mod_fname = mod.path.empty() ? mod.name : mod.path.filename().string();
            if (case_insensitive) {
                if (to_lower_ascii(mod_fname) == req_lower || to_lower_ascii(mod.name) == req_lower) {
                    return &mod;
                }
            } else {
                if (mod_fname == req_fname || mod.name == req_fname ||
                    (!mod.path.empty() && mod.path.generic_string() == requested_name)) {
                    return &mod;
                }
                // Match versioned SONAME e.g. requested "libc.so.6" against "/lib/.../libc-2.35.so" if name matches prefix
                if (mod_fname.starts_with(req_fname + ".")) {
                    return &mod;
                }
            }
        }
        return nullptr;
    }

    [[nodiscard]] CandidateResult resolve_pe_dependency(
        const IBinaryImage& parent_img,
        const std::filesystem::path& parent_origin,
        std::string_view requested_name) {
        CandidateResult res;
        std::filesystem::path mismatch_path;
        std::string mismatch_reason;

        auto consider_file = [&](const std::filesystem::path& found_path,
                                 std::string_view source_label) -> bool {
            const ParsedModuleEntry* ent = load_or_get_disk_module(found_path);
            if (ent == nullptr || !ent->image) {
                return false;
            }
            if (!images_compatible(parent_img, *ent->image)) {
                if (mismatch_path.empty()) {
                    mismatch_path = found_path;
                    mismatch_reason = std::format(
                        "Architecture mismatch in {}: expected {}, found {}",
                        source_label,
                        format_image_arch_desc(parent_img),
                        format_image_arch_desc(*ent->image));
                }
                return false;
            }
            res.path = found_path;
            res.parsed_image = ent->image.get();
            res.live_base_va = ent->live_base_va;
            res.status = ent->live_base_va.has_value()
                             ? DependencyResolutionStatus::ResolvedInLiveProcess
                             : DependencyResolutionStatus::ResolvedOnDisk;
            res.reason = ent->live_base_va.has_value()
                             ? std::format("Resolved via {} (mapped in live process at {:#x})",
                                           source_label, *ent->live_base_va)
                             : std::format("Resolved via {} ({})", source_label, found_path.generic_string());
            return true;
        };

        // 1. Importing binary's directory (and root binary's directory)
        if (!parent_origin.empty()) {
            if (auto p = probe_directory_for_file(parent_origin, requested_name, true, res.searched_paths)) {
                if (consider_file(*p, "application/module directory")) {
                    return res;
                }
            }
        }
        const auto root_dir = !opts_.root_path.empty() ? opts_.root_path.parent_path() : std::filesystem::path{};
        if (!root_dir.empty() && root_dir != parent_origin) {
            if (auto p = probe_directory_for_file(root_dir, requested_name, true, res.searched_paths)) {
                if (consider_file(*p, "root executable directory")) {
                    return res;
                }
            }
        }

        // 2. User-configured search roots
        for (const auto& sr : opts_.search_roots) {
            if (auto p = probe_directory_for_file(sr, requested_name, true, res.searched_paths)) {
                if (consider_file(*p, std::format("configured search root '{}'", sr.generic_string()))) {
                    return res;
                }
            }
        }

        // 3. Live loaded module paths when attached
        if (const ModuleInfo* live_mod = find_matching_live_module(requested_name, true)) {
            if (!live_mod->path.empty()) {
                push_unique_path(res.searched_paths, live_mod->path);
            }
            if (const ParsedModuleEntry* ent = load_or_get_live_module(*live_mod)) {
                if (images_compatible(parent_img, *ent->image)) {
                    res.status = DependencyResolutionStatus::ResolvedInLiveProcess;
                    res.path = ent->path;
                    res.parsed_image = ent->image.get();
                    res.live_base_va = ent->live_base_va;
                    res.reason = std::format("Resolved from attached live process module at {:#x}",
                                             live_mod->base_address);
                    return res;
                }
                if (mismatch_path.empty()) {
                    mismatch_path = live_mod->path;
                    mismatch_reason = std::format(
                        "Architecture mismatch in live module: expected {}, found {}",
                        format_image_arch_desc(parent_img),
                        format_image_arch_desc(*ent->image));
                }
            }
        }

        // 4. Windows API Set virtual contract DLL recognition (after checking explicit roots/live modules!)
        if (is_windows_api_set_dll(requested_name)) {
            res.status = DependencyResolutionStatus::VirtualApiSet;
            res.reason = "Windows API Set virtual OS contract DLL (routed via ApiSetSchema at runtime)";
            return res;
        }

        // 5. OS system directories (System32 / SysWOW64) when available
        if (opts_.include_default_system_dirs) {
            std::vector<std::filesystem::path> sys_dirs;
            if (!opts_.sysroot.empty()) {
                sys_dirs.push_back(opts_.sysroot / (parent_img.is_64bit() ? "Windows/System32" : "Windows/SysWOW64"));
                sys_dirs.push_back(opts_.sysroot / "System32");
            }
            if (const char* windir = std::getenv("SystemRoot"); windir != nullptr && *windir != '\0') {
                const std::filesystem::path win(windir);
                sys_dirs.push_back(win / (parent_img.is_64bit() ? "System32" : "SysWOW64"));
                sys_dirs.push_back(win);
            }
            for (const auto& sd : sys_dirs) {
                if (auto p = probe_directory_for_file(sd, requested_name, true, res.searched_paths)) {
                    if (consider_file(*p, std::format("OS system directory '{}'", sd.generic_string()))) {
                        return res;
                    }
                }
            }
        }

        if (!mismatch_path.empty()) {
            res.status = DependencyResolutionStatus::ArchitectureMismatch;
            res.path = mismatch_path;
            res.reason = mismatch_reason;
            return res;
        }

        res.status = DependencyResolutionStatus::Unresolved;
        res.reason = std::format("Unresolved PE import after searching {} candidate path(s)",
                                 res.searched_paths.size());
        return res;
    }

    [[nodiscard]] CandidateResult resolve_elf_dependency(
        const IBinaryImage& parent_img,
        const DependencyNode& parent_node,
        const std::filesystem::path& parent_origin,
        const std::vector<std::pair<std::string, std::filesystem::path>>& inherited_rpaths,
        std::string_view requested_name) {
        CandidateResult res;
        std::filesystem::path mismatch_path;
        std::string mismatch_reason;

        const std::string lib_tok = !opts_.elf_lib_token.empty()
                                        ? opts_.elf_lib_token
                                        : default_elf_lib_token(parent_img);
        const std::string plat_tok = !opts_.elf_platform_token.empty()
                                         ? opts_.elf_platform_token
                                         : default_elf_platform_token(parent_img);

        auto consider_file = [&](const std::filesystem::path& found_path,
                                 std::string_view source_label) -> bool {
            const ParsedModuleEntry* ent = load_or_get_disk_module(found_path);
            if (ent == nullptr || !ent->image) {
                return false;
            }
            if (!images_compatible(parent_img, *ent->image)) {
                if (mismatch_path.empty()) {
                    mismatch_path = found_path;
                    mismatch_reason = std::format(
                        "Architecture mismatch in {}: expected {}, found {}",
                        source_label,
                        format_image_arch_desc(parent_img),
                        format_image_arch_desc(*ent->image));
                }
                return false;
            }
            res.path = found_path;
            res.parsed_image = ent->image.get();
            res.live_base_va = ent->live_base_va;
            res.status = ent->live_base_va.has_value()
                             ? DependencyResolutionStatus::ResolvedInLiveProcess
                             : DependencyResolutionStatus::ResolvedOnDisk;
            res.reason = ent->live_base_va.has_value()
                             ? std::format("Resolved via {} (mapped in live process at {:#x})",
                                           source_label, *ent->live_base_va)
                             : std::format("Resolved via {}", source_label);
            return true;
        };

        auto probe_expanded_rpath = [&](std::string_view raw_seg,
                                        const std::filesystem::path& seg_origin,
                                        std::string_view tag_name) -> bool {
            std::filesystem::path eff_origin = seg_origin;
            if (eff_origin.empty() && raw_seg.find("ORIGIN") != std::string_view::npos) {
                eff_origin = std::filesystem::path(".");
                push_unique_string(res.origin_assumptions,
                                   "$ORIGIN = . (in-memory image without file path)");
            }
            const std::string expanded = expand_elf_dynamic_tokens(
                raw_seg, eff_origin, lib_tok, plat_tok, &res.origin_assumptions);
            const std::filesystem::path dir(expanded);
            if (auto p = probe_directory_for_file(dir, requested_name, false, res.searched_paths)) {
                if (consider_file(*p, std::format("{} '{}' -> '{}'", tag_name, raw_seg, dir.generic_string()))) {
                    return true;
                }
            }
            return false;
        };

        // Direct slash-containing path (e.g. PT_INTERP /lib64/ld-linux-x86-64.so.2 or $ORIGIN/libfoo.so)
        if (requested_name.find('/') != std::string_view::npos) {
            const std::string expanded = expand_elf_dynamic_tokens(
                requested_name, parent_origin, lib_tok, plat_tok, &res.origin_assumptions);
            if (const ModuleInfo* live_mod = find_matching_live_module(expanded, false)) {
                if (const ParsedModuleEntry* ent = load_or_get_live_module(*live_mod)) {
                    if (images_compatible(parent_img, *ent->image)) {
                        res.status = DependencyResolutionStatus::ResolvedInLiveProcess;
                        res.path = ent->path;
                        res.parsed_image = ent->image.get();
                        res.live_base_va = ent->live_base_va;
                        res.reason = std::format("Resolved direct path in attached live process at {:#x}",
                                                 live_mod->base_address);
                        return res;
                    }
                }
            }

            std::vector<std::pair<std::filesystem::path, std::string>> direct_candidates;
            const std::filesystem::path exp_path(expanded);
            if (exp_path.is_relative() && !parent_origin.empty()) {
                direct_candidates.emplace_back((parent_origin / exp_path).lexically_normal(),
                                               "relative module path");
            }
            if (!opts_.sysroot.empty() && expanded.starts_with('/')) {
                direct_candidates.emplace_back((opts_.sysroot / expanded.substr(1)).lexically_normal(),
                                               "sysroot direct path");
            }
            if (opts_.include_default_system_dirs || exp_path.is_relative()) {
                direct_candidates.emplace_back(exp_path.lexically_normal(), "direct ELF path");
            }

            for (const auto& [cand, label] : direct_candidates) {
                push_unique_path(res.searched_paths, cand);
                std::error_code ec;
                if (std::filesystem::is_regular_file(cand, ec)) {
                    if (consider_file(cand, label)) {
                        return res;
                    }
                }
            }
        } else {
            // 1. DT_RPATH (only when parent's DT_RUNPATH is empty!)
            if (parent_node.elf_runpaths.empty()) {
                for (const auto& [rp, rp_origin] : inherited_rpaths) {
                    if (probe_expanded_rpath(rp, rp_origin, "DT_RPATH")) {
                        return res;
                    }
                }
            }

            // 2. Configured search roots + LD_LIBRARY_PATH
            for (const auto& sr : opts_.search_roots) {
                if (auto p = probe_directory_for_file(sr, requested_name, false, res.searched_paths)) {
                    if (consider_file(*p, std::format("configured search root '{}'", sr.generic_string()))) {
                        return res;
                    }
                }
            }
            for (const auto& lp : opts_.ld_library_paths) {
                if (auto p = probe_directory_for_file(lp, requested_name, false, res.searched_paths)) {
                    if (consider_file(*p, std::format("LD_LIBRARY_PATH '{}'", lp.generic_string()))) {
                        return res;
                    }
                }
            }
            for (const auto& lp : env_ld_paths_) {
                if (auto p = probe_directory_for_file(lp, requested_name, false, res.searched_paths)) {
                    if (consider_file(*p, std::format("env LD_LIBRARY_PATH '{}'", lp.generic_string()))) {
                        return res;
                    }
                }
            }

            // 3. DT_RUNPATH
            for (const std::string& rnp : parent_node.elf_runpaths) {
                if (probe_expanded_rpath(rnp, parent_origin, "DT_RUNPATH")) {
                    return res;
                }
            }

            // 4. Live process ModuleInfo / link_map paths when attached
            if (const ModuleInfo* live_mod = find_matching_live_module(requested_name, false)) {
                if (!live_mod->path.empty()) {
                    push_unique_path(res.searched_paths, live_mod->path);
                }
                if (const ParsedModuleEntry* ent = load_or_get_live_module(*live_mod)) {
                    if (images_compatible(parent_img, *ent->image)) {
                        res.status = DependencyResolutionStatus::ResolvedInLiveProcess;
                        res.path = ent->path;
                        res.parsed_image = ent->image.get();
                        res.live_base_va = ent->live_base_va;
                        res.reason = std::format("Resolved from attached live process module at {:#x}",
                                                 live_mod->base_address);
                        return res;
                    }
                    if (mismatch_path.empty()) {
                        mismatch_path = live_mod->path;
                        mismatch_reason = std::format(
                            "Architecture mismatch in live module: expected {}, found {}",
                            format_image_arch_desc(parent_img),
                            format_image_arch_desc(*ent->image));
                    }
                }
            }

            // 5. Standard multiarch & system library directories
            if (opts_.include_default_system_dirs) {
                std::vector<std::filesystem::path> sys_dirs;
                const auto add_sys = [&](std::string_view rel) {
                    if (!opts_.sysroot.empty()) {
                        sys_dirs.push_back((opts_.sysroot / rel.substr(rel.starts_with('/') ? 1 : 0)).lexically_normal());
                    } else {
                        sys_dirs.emplace_back(rel);
                    }
                };
                for (const std::string& tuple : elf_multiarch_tuples(parent_img)) {
                    add_sys("/lib/" + tuple);
                    add_sys("/usr/lib/" + tuple);
                }
                if (parent_img.is_64bit()) {
                    add_sys("/lib64");
                    add_sys("/usr/lib64");
                }
                add_sys("/lib");
                add_sys("/usr/lib");
                add_sys("/usr/local/lib");

                for (const auto& sd : sys_dirs) {
                    if (auto p = probe_directory_for_file(sd, requested_name, false, res.searched_paths)) {
                        if (consider_file(*p, std::format("system library path '{}'", sd.generic_string()))) {
                            return res;
                        }
                    }
                }
            }
        }

        if (!mismatch_path.empty()) {
            res.status = DependencyResolutionStatus::ArchitectureMismatch;
            res.path = mismatch_path;
            res.reason = mismatch_reason;
            return res;
        }

        res.status = DependencyResolutionStatus::Unresolved;
        res.reason = std::format("Unresolved ELF dependency '{}' after searching {} path(s)",
                                 requested_name, res.searched_paths.size());
        return res;
    }

    [[nodiscard]] std::vector<ImportedSymbolBinding> bind_pe_symbols(
        const std::vector<RequestedSymbolRef>& req_syms,
        DependencyResolutionStatus child_status,
        const IBinaryImage* child_img) const {
        std::vector<ImportedSymbolBinding> out;
        out.reserve(req_syms.size());

        std::unordered_map<std::string, const ExportEntry*> exp_by_name;
        std::unordered_map<std::uint32_t, const ExportEntry*> exp_by_ord;
        if (child_img != nullptr) {
            for (const ExportEntry& exp : child_img->exports()) {
                if (!exp.name.empty()) {
                    exp_by_name.try_emplace(exp.name, &exp);
                }
                if (exp.ordinal != 0) {
                    exp_by_ord.try_emplace(exp.ordinal, &exp);
                }
            }
        }

        for (const RequestedSymbolRef& req : req_syms) {
            ImportedSymbolBinding b;
            b.name = req.name;
            b.ordinal = req.ordinal;
            b.import_by_ordinal = req.import_by_ordinal;
            b.delay_load = req.delay_load;
            b.weak_symbol = req.weak_symbol;
            b.call_site_va = req.call_site_va;
            b.note = req.note;

            if (child_status == DependencyResolutionStatus::VirtualApiSet) {
                b.status = ImportedSymbolStatus::UncheckedVirtualApiSet;
            } else if (child_img == nullptr ||
                       (child_status != DependencyResolutionStatus::ResolvedOnDisk &&
                        child_status != DependencyResolutionStatus::ResolvedInLiveProcess)) {
                b.status = ImportedSymbolStatus::UncheckedTargetUnavailable;
            } else {
                const ExportEntry* matched = nullptr;
                if (req.import_by_ordinal) {
                    if (auto it = exp_by_ord.find(req.ordinal); it != exp_by_ord.end()) {
                        matched = it->second;
                    }
                } else {
                    if (auto it = exp_by_name.find(req.name); it != exp_by_name.end()) {
                        matched = it->second;
                    }
                }

                if (matched != nullptr) {
                    b.resolved_export_va = matched->virtual_address;
                    if (!matched->forwarder.empty()) {
                        b.status = ImportedSymbolStatus::BoundForwardedExport;
                        b.forwarded_to = matched->forwarder;
                    } else {
                        b.status = ImportedSymbolStatus::BoundExport;
                    }
                } else {
                    b.status = ImportedSymbolStatus::UnboundMissingExport;
                }
            }
            out.push_back(std::move(b));
        }
        return out;
    }

    std::size_t get_or_create_node(std::string_view requested_name,
                                   const CandidateResult& cand,
                                   const IBinaryImage*& child_img_out) {
        child_img_out = cand.parsed_image;
        std::string node_key;
        if ((cand.status == DependencyResolutionStatus::ResolvedOnDisk ||
             cand.status == DependencyResolutionStatus::ResolvedInLiveProcess) &&
            !cand.path.empty()) {
            node_key = "path:" + normalize_path_key(cand.path).generic_string();
        } else if (cand.status == DependencyResolutionStatus::ResolvedInLiveProcess &&
                   cand.live_base_va.has_value()) {
            node_key = std::format("live:{:#x}", *cand.live_base_va);
        } else if (cand.status == DependencyResolutionStatus::ArchitectureMismatch &&
                   !cand.path.empty()) {
            node_key = "mismatch:" + normalize_path_key(cand.path).generic_string();
        } else if (cand.status == DependencyResolutionStatus::VirtualApiSet) {
            node_key = "apiset:" + to_lower_ascii(requested_name);
        } else {
            node_key = "missing:" + std::string(requested_name);
        }

        if (auto it = node_id_by_key_.find(node_key); it != node_id_by_key_.end()) {
            const std::size_t existing_id = it->second;
            if (child_img_out == nullptr) {
                if (auto img_it = image_by_node_id_.find(existing_id); img_it != image_by_node_id_.end()) {
                    child_img_out = img_it->second;
                }
            }
            return existing_id;
        }

        const std::size_t new_id = graph_.nodes.size();
        DependencyNode node;
        node.id = new_id;
        node.requested_name = std::string(requested_name);
        node.display_name = !cand.path.empty() ? cand.path.filename().string() : std::string(requested_name);
        node.resolved_path = cand.path;
        node.status = cand.status;
        node.resolution_reason = cand.reason;
        node.searched_paths = cand.searched_paths;
        node.origin_assumptions = cand.origin_assumptions;
        node.live_base_va = cand.live_base_va;

        if (cand.parsed_image != nullptr) {
            node.format = cand.parsed_image->format();
            node.architecture = cand.parsed_image->architecture();
            node.endianness = cand.parsed_image->endianness();
            node.is_64bit = cand.parsed_image->is_64bit();
            node.export_count = cand.parsed_image->exports().size();
            extract_elf_dynamic_metadata(*cand.parsed_image,
                                         node.soname,
                                         node.elf_rpaths,
                                         node.elf_runpaths,
                                         node.elf_interpreter);
            image_by_node_id_[new_id] = cand.parsed_image;
        } else if (cand.status == DependencyResolutionStatus::ArchitectureMismatch && !cand.path.empty()) {
            if (const ParsedModuleEntry* mis = load_or_get_disk_module(cand.path); mis != nullptr && mis->image) {
                node.format = mis->image->format();
                node.architecture = mis->image->architecture();
                node.endianness = mis->image->endianness();
                node.is_64bit = mis->image->is_64bit();
            }
        }

        graph_.nodes.push_back(std::move(node));
        node_id_by_key_.emplace(node_key, new_id);
        return new_id;
    }

    void clone_cached_subtree(std::size_t node_id,
                              std::uint32_t current_depth,
                              std::vector<std::size_t>& ancestors,
                              DependencyTreeItem& target_item) {
        auto cached_it = expanded_subtree_by_node_.find(node_id);
        if (cached_it == expanded_subtree_by_node_.end()) {
            return;
        }
        if (current_depth >= opts_.max_depth) {
            if (!cached_it->second.empty()) {
                target_item.truncated_by_depth = true;
            }
            return;
        }
        ancestors.push_back(node_id);
        for (const DependencyTreeItem& tmpl : cached_it->second) {
            DependencyTreeItem copy = tmpl;
            copy.depth = current_depth + 1;
            copy.children.clear();
            if (std::ranges::find(ancestors, copy.node_id) != ancestors.end()) {
                copy.is_cycle = true;
                copy.status = DependencyResolutionStatus::CycleSkipped;
            } else if (!tmpl.is_cycle) {
                clone_cached_subtree(copy.node_id, current_depth + 1, ancestors, copy);
            }
            target_item.children.push_back(std::move(copy));
        }
        ancestors.pop_back();
    }

    void expand_node(std::size_t parent_id,
                     const IBinaryImage& parent_img,
                     const std::filesystem::path& parent_origin,
                     const std::vector<std::pair<std::string, std::filesystem::path>>& inherited_rpaths,
                     std::uint32_t depth,
                     std::vector<std::size_t>& ancestors,
                     DependencyTreeItem& tree_out) {
        expanded_nodes_.insert(parent_id);

        const auto requests = collect_direct_requests(parent_img);
        if (requests.empty()) {
            if (parent_img.format() == Format::ELF) {
                for (const RequestedSymbolRef& u : collect_elf_undefined_symbols(parent_img)) {
                    if (!u.weak_symbol) {
                        ImportedSymbolBinding b;
                        b.name = u.name;
                        b.call_site_va = u.call_site_va;
                        b.status = ImportedSymbolStatus::UnboundMissingExport;
                        b.note = "No DT_NEEDED libraries declared to satisfy strong undefined symbol";
                        graph_.nodes[parent_id].unresolved_symbols.push_back(std::move(b));
                    }
                }
            }
            expanded_subtree_by_node_[parent_id] = {};
            return;
        }

        if (depth >= opts_.max_depth) {
            tree_out.truncated_by_depth = true;
            return;
        }

        struct PendingChild {
            std::size_t edge_idx{0};
            std::size_t child_id{0};
            const IBinaryImage* child_img{nullptr};
            DependencyEdgeKind kind{DependencyEdgeKind::StandardImport};
            DependencyResolutionStatus status{DependencyResolutionStatus::Unresolved};
            bool is_cycle{false};
            bool already_expanded{false};
        };
        std::vector<PendingChild> pending;
        pending.reserve(requests.size());

        for (const RequestedDependency& req : requests) {
            const DependencyNode parent_snapshot = graph_.nodes[parent_id];
            CandidateResult cand =
                parent_img.format() == Format::PE
                    ? resolve_pe_dependency(parent_img, parent_origin, req.requested_name)
                    : resolve_elf_dependency(parent_img, parent_snapshot, parent_origin,
                                             inherited_rpaths, req.requested_name);

            const IBinaryImage* child_img = nullptr;
            const std::size_t child_id = get_or_create_node(req.requested_name, cand, child_img);
            const bool is_cycle = std::ranges::find(ancestors, child_id) != ancestors.end();
            const bool already_expanded = expanded_nodes_.contains(child_id);

            DependencyEdge edge;
            edge.parent_node_id = parent_id;
            edge.child_node_id = child_id;
            edge.requested_name = req.requested_name;
            edge.kind = req.kind;
            edge.resolution_status = is_cycle ? DependencyResolutionStatus::CycleSkipped : cand.status;
            edge.resolved_path = cand.path;
            edge.resolution_reason = is_cycle
                                         ? std::format("Cyclic dependency skipped ({} -> {})",
                                                       graph_.nodes[parent_id].display_name,
                                                       graph_.nodes[child_id].display_name)
                                         : cand.reason;
            edge.searched_paths = std::move(cand.searched_paths);
            edge.origin_assumptions = std::move(cand.origin_assumptions);

            if (parent_img.format() == Format::PE) {
                edge.symbol_bindings = bind_pe_symbols(req.symbols, cand.status, child_img);
            }

            const std::size_t edge_idx = graph_.edges.size();
            graph_.edges.push_back(std::move(edge));

            pending.push_back(PendingChild{
                .edge_idx = edge_idx,
                .child_id = child_id,
                .child_img = child_img,
                .kind = req.kind,
                .status = is_cycle ? DependencyResolutionStatus::CycleSkipped : cand.status,
                .is_cycle = is_cycle,
                .already_expanded = already_expanded,
            });
        }

        // Expand children first so ELF transitive export maps are also available if needed!
        for (const PendingChild& pc : pending) {
            const bool already_expanded = pc.already_expanded || expanded_nodes_.contains(pc.child_id);
            DependencyTreeItem item;
            item.node_id = pc.child_id;
            item.edge_index = pc.edge_idx;
            item.requested_name = graph_.edges[pc.edge_idx].requested_name;
            item.edge_kind = pc.kind;
            item.status = pc.status;
            item.depth = depth + 1;
            item.is_cycle = pc.is_cycle;
            item.is_diamond_ref = !pc.is_cycle && already_expanded;

            if (pc.is_cycle) {
                ++cycle_edge_count_;
            } else if (already_expanded) {
                clone_cached_subtree(pc.child_id, depth + 1, ancestors, item);
            } else if (pc.child_img != nullptr &&
                       (pc.status == DependencyResolutionStatus::ResolvedOnDisk ||
                        pc.status == DependencyResolutionStatus::ResolvedInLiveProcess)) {
                ancestors.push_back(pc.child_id);
                const std::filesystem::path child_origin =
                    !graph_.nodes[pc.child_id].resolved_path.empty()
                        ? graph_.nodes[pc.child_id].resolved_path.parent_path()
                        : parent_origin;
                std::vector<std::pair<std::string, std::filesystem::path>> child_rpaths;
                if (graph_.nodes[pc.child_id].elf_runpaths.empty()) {
                    child_rpaths = inherited_rpaths;
                    for (const std::string& rp : graph_.nodes[pc.child_id].elf_rpaths) {
                        child_rpaths.emplace_back(rp, child_origin);
                    }
                }
                expand_node(pc.child_id, *pc.child_img, child_origin, child_rpaths,
                            depth + 1, ancestors, item);
                ancestors.pop_back();
            }

            tree_out.children.push_back(std::move(item));
        }

        // Bind ELF undefined dynamic symbols across resolved child dependencies
        if (parent_img.format() == Format::ELF) {
            bind_elf_symbols_for_parent(parent_id, parent_img, pending);
        }

        expanded_subtree_by_node_[parent_id] = tree_out.children;
    }

    template <typename PendingVec>
    void bind_elf_symbols_for_parent(std::size_t parent_id,
                                     const IBinaryImage& parent_img,
                                     const PendingVec& pending) {
        const auto undefs = collect_elf_undefined_symbols(parent_img);
        if (undefs.empty()) {
            return;
        }

        // Collect export maps for each direct child and any reachable resolved descendants
        struct ChildExports {
            std::size_t edge_idx{0};
            std::size_t child_id{0};
            DependencyEdgeKind kind{DependencyEdgeKind::StandardImport};
            bool resolved{false};
            std::unordered_map<std::string, std::uint64_t> exports{};
        };
        std::vector<ChildExports> child_maps;
        bool all_needed_resolved = true;
        std::optional<std::size_t> first_needed_edge_idx;

        for (const auto& pc : pending) {
            ChildExports ce;
            ce.edge_idx = pc.edge_idx;
            ce.child_id = pc.child_id;
            ce.kind = pc.kind;
            const auto st = graph_.nodes[pc.child_id].status;
            ce.resolved = (st == DependencyResolutionStatus::ResolvedOnDisk ||
                           st == DependencyResolutionStatus::ResolvedInLiveProcess ||
                           st == DependencyResolutionStatus::RootModule);
            if (pc.kind == DependencyEdgeKind::StandardImport) {
                if (!first_needed_edge_idx.has_value()) {
                    first_needed_edge_idx = pc.edge_idx;
                }
                if (!ce.resolved) {
                    all_needed_resolved = false;
                }
            }
            if (ce.resolved) {
                if (auto it = image_by_node_id_.find(pc.child_id); it != image_by_node_id_.end() && it->second != nullptr) {
                    ce.exports = build_elf_export_map(*it->second);
                } else if (pc.child_id == 0) {
                    ce.exports = build_elf_export_map(root_image_);
                }
            }
            child_maps.push_back(std::move(ce));
        }

        // Also gather transitive exports in BFS order from resolved descendants (ld.so global scope)
        std::unordered_map<std::string, std::pair<std::uint64_t, std::string>> transitive_exports;
        {
            std::unordered_set<std::size_t> visited{parent_id};
            std::vector<std::size_t> queue;
            for (const auto& ce : child_maps) {
                if (ce.resolved && visited.insert(ce.child_id).second) {
                    queue.push_back(ce.child_id);
                }
            }
            for (std::size_t qi = 0; qi < queue.size(); ++qi) {
                const std::size_t cur = queue[qi];
                for (const DependencyEdge& e : graph_.edges) {
                    if (e.parent_node_id != cur) {
                        continue;
                    }
                    const std::size_t desc = e.child_node_id;
                    const auto st = graph_.nodes[desc].status;
                    if (st != DependencyResolutionStatus::ResolvedOnDisk &&
                        st != DependencyResolutionStatus::ResolvedInLiveProcess) {
                        continue;
                    }
                    if (visited.insert(desc).second) {
                        queue.push_back(desc);
                    }
                    if (auto img_it = image_by_node_id_.find(desc);
                        img_it != image_by_node_id_.end() && img_it->second != nullptr) {
                        for (const auto& [sym_name, sym_va] : build_elf_export_map(*img_it->second)) {
                            transitive_exports.try_emplace(
                                sym_name, std::make_pair(sym_va, graph_.nodes[desc].display_name));
                        }
                    }
                }
            }
        }

        for (const RequestedSymbolRef& u : undefs) {
            bool matched_direct = false;
            for (const auto& ce : child_maps) {
                if (!ce.resolved) {
                    continue;
                }
                if (auto it = ce.exports.find(u.name); it != ce.exports.end()) {
                    ImportedSymbolBinding b;
                    b.name = u.name;
                    b.weak_symbol = u.weak_symbol;
                    b.call_site_va = u.call_site_va;
                    b.resolved_export_va = it->second;
                    b.status = ImportedSymbolStatus::BoundExport;
                    graph_.edges[ce.edge_idx].symbol_bindings.push_back(std::move(b));
                    matched_direct = true;
                    break;
                }
            }
            if (matched_direct) {
                continue;
            }

            if (auto tr_it = transitive_exports.find(u.name); tr_it != transitive_exports.end()) {
                if (first_needed_edge_idx.has_value()) {
                    ImportedSymbolBinding b;
                    b.name = u.name;
                    b.weak_symbol = u.weak_symbol;
                    b.call_site_va = u.call_site_va;
                    b.resolved_export_va = tr_it->second.first;
                    b.status = ImportedSymbolStatus::BoundExport;
                    b.note = std::format("Satisfied transitively by {}", tr_it->second.second);
                    graph_.edges[*first_needed_edge_idx].symbol_bindings.push_back(std::move(b));
                }
                continue;
            }

            if (u.weak_symbol) {
                if (first_needed_edge_idx.has_value()) {
                    ImportedSymbolBinding b;
                    b.name = u.name;
                    b.weak_symbol = true;
                    b.call_site_va = u.call_site_va;
                    b.status = ImportedSymbolStatus::BoundWeakOptional;
                    graph_.edges[*first_needed_edge_idx].symbol_bindings.push_back(std::move(b));
                }
                continue;
            }

            if (all_needed_resolved) {
                ImportedSymbolBinding b;
                b.name = u.name;
                b.call_site_va = u.call_site_va;
                b.status = ImportedSymbolStatus::UnboundMissingExport;
                b.note = "Not exported by any resolved DT_NEEDED library";
                graph_.nodes[parent_id].unresolved_symbols.push_back(b);
                if (first_needed_edge_idx.has_value()) {
                    graph_.edges[*first_needed_edge_idx].symbol_bindings.push_back(std::move(b));
                }
            } else if (first_needed_edge_idx.has_value()) {
                ImportedSymbolBinding b;
                b.name = u.name;
                b.call_site_va = u.call_site_va;
                b.status = ImportedSymbolStatus::UncheckedTargetUnavailable;
                b.note = "Cannot verify while one or more DT_NEEDED libraries are unresolved";
                graph_.edges[*first_needed_edge_idx].symbol_bindings.push_back(std::move(b));
            }
        }
    }

    void compute_summary() {
        DependencySummary s{};
        std::unordered_set<std::size_t> direct_nodes;
        for (const DependencyEdge& e : graph_.edges) {
            if (e.parent_node_id == 0 && e.child_node_id != 0) {
                direct_nodes.insert(e.child_node_id);
            }
        }
        s.direct_dependencies = direct_nodes.size();
        const std::size_t non_root_nodes = graph_.nodes.size() > 1 ? (graph_.nodes.size() - 1) : 0;
        s.transitive_dependencies = non_root_nodes >= s.direct_dependencies
                                        ? (non_root_nodes - s.direct_dependencies)
                                        : 0;

        for (std::size_t i = 1; i < graph_.nodes.size(); ++i) {
            switch (graph_.nodes[i].status) {
                case DependencyResolutionStatus::ResolvedOnDisk:
                    ++s.resolved_count;
                    break;
                case DependencyResolutionStatus::ResolvedInLiveProcess:
                    ++s.resolved_count;
                    ++s.resolved_live_count;
                    break;
                case DependencyResolutionStatus::VirtualApiSet:
                    ++s.virtual_api_sets;
                    break;
                case DependencyResolutionStatus::Unresolved:
                    ++s.missing_libraries;
                    break;
                case DependencyResolutionStatus::ArchitectureMismatch:
                    ++s.architecture_mismatches;
                    break;
                case DependencyResolutionStatus::RootModule:
                case DependencyResolutionStatus::CycleSkipped:
                    break;
            }
        }
        s.cycle_edges = cycle_edge_count_;

        std::unordered_set<std::string> unique_missing_syms;
        for (const DependencyEdge& e : graph_.edges) {
            for (const ImportedSymbolBinding& b : e.symbol_bindings) {
                if (b.status == ImportedSymbolStatus::UnboundMissingExport) {
                    unique_missing_syms.insert(
                        std::format("{}->{}", e.parent_node_id, b.name));
                }
            }
        }
        for (const DependencyNode& n : graph_.nodes) {
            for (const ImportedSymbolBinding& b : n.unresolved_symbols) {
                if (b.status == ImportedSymbolStatus::UnboundMissingExport) {
                    unique_missing_syms.insert(std::format("{}->{}", n.id, b.name));
                }
            }
        }
        s.unresolved_symbols = unique_missing_syms.size();
        graph_.summary = s;
    }

    const IBinaryImage& root_image_;
    const DependencyResolveOptions& opts_;
    IProcessSession* live_session_{nullptr};
    std::vector<ModuleInfo> live_modules_{};
    std::vector<std::filesystem::path> env_ld_paths_{};

    DependencyGraph graph_{};
    std::unordered_map<std::string, ParsedModuleEntry> parsed_cache_{};
    std::unordered_map<std::string, std::size_t> node_id_by_key_{};
    std::unordered_map<std::size_t, const IBinaryImage*> image_by_node_id_{};
    std::unordered_set<std::size_t> expanded_nodes_{};
    std::unordered_map<std::size_t, std::vector<DependencyTreeItem>> expanded_subtree_by_node_{};
    std::size_t cycle_edge_count_{0};
};

} // namespace

bool is_windows_api_set_dll(std::string_view dll_name) noexcept {
    const auto lower_ch = [](char c) noexcept -> char {
        return (c >= 'A' && c <= 'Z') ? static_cast<char>(c - 'A' + 'a') : c;
    };
    const auto istarts_with = [&](std::string_view sv, std::string_view prefix) noexcept -> bool {
        if (sv.size() < prefix.size()) return false;
        for (std::size_t i = 0; i < prefix.size(); ++i) {
            if (lower_ch(sv[i]) != prefix[i]) return false;
        }
        return true;
    };
    const auto iends_with = [&](std::string_view sv, std::string_view suffix) noexcept -> bool {
        if (sv.size() < suffix.size()) return false;
        const std::size_t base = sv.size() - suffix.size();
        for (std::size_t i = 0; i < suffix.size(); ++i) {
            if (lower_ch(sv[base + i]) != suffix[i]) return false;
        }
        return true;
    };

    const std::size_t sep = dll_name.find_last_of("/\\");
    std::string_view stem = (sep == std::string_view::npos) ? dll_name : dll_name.substr(sep + 1u);
    if (iends_with(stem, ".dll")) {
        stem.remove_suffix(4u);
    }
    return istarts_with(stem, "api-ms-win-") ||
           istarts_with(stem, "ext-ms-win-") ||
           istarts_with(stem, "api-ms-onecoreuap-");
}

std::string expand_elf_dynamic_tokens(
    std::string_view raw_path,
    const std::filesystem::path& origin_dir,
    std::string_view lib_token,
    std::string_view platform_token,
    std::vector<std::string>* assumptions_out) {
    const std::string origin_str = origin_dir.empty() ? "." : origin_dir.generic_string();
    const std::string lib_str = lib_token.empty() ? "lib" : std::string(lib_token);
    const std::string plat_str = platform_token.empty() ? "unknown" : std::string(platform_token);

    std::string out;
    out.reserve(raw_path.size() + origin_str.size());

    auto match_token = [&](std::size_t pos, std::string_view tok_name, std::size_t& consumed) -> bool {
        if (raw_path.substr(pos).starts_with("${" + std::string(tok_name) + "}")) {
            consumed = tok_name.size() + 3;
            return true;
        }
        if (raw_path.substr(pos).starts_with("$" + std::string(tok_name))) {
            const std::size_t after = pos + 1 + tok_name.size();
            if (after >= raw_path.size() ||
                (!std::isalnum(static_cast<unsigned char>(raw_path[after])) && raw_path[after] != '_')) {
                consumed = 1 + tok_name.size();
                return true;
            }
        }
        return false;
    };

    std::size_t i = 0;
    while (i < raw_path.size()) {
        if (raw_path[i] == '$') {
            std::size_t consumed = 0;
            if (match_token(i, "ORIGIN", consumed)) {
                out += origin_str;
                if (assumptions_out != nullptr) {
                    push_unique_string(*assumptions_out, "$ORIGIN = " + origin_str);
                }
                i += consumed;
                continue;
            }
            if (match_token(i, "LIB", consumed)) {
                out += lib_str;
                if (assumptions_out != nullptr) {
                    push_unique_string(*assumptions_out, "$LIB = " + lib_str);
                }
                i += consumed;
                continue;
            }
            if (match_token(i, "PLATFORM", consumed)) {
                out += plat_str;
                if (assumptions_out != nullptr) {
                    push_unique_string(*assumptions_out, "$PLATFORM = " + plat_str);
                }
                i += consumed;
                continue;
            }
        }
        out.push_back(raw_path[i]);
        ++i;
    }
    return out;
}

std::vector<std::filesystem::path> parse_search_roots_list(std::string_view text) {
    std::vector<std::filesystem::path> roots;
    std::size_t i = 0;
    while (i < text.size()) {
        while (i < text.size() && std::isspace(static_cast<unsigned char>(text[i]))) {
            ++i;
        }
        if (i >= text.size()) {
            break;
        }
        // On Windows paths like C:\foo;D:\bar, avoid splitting on drive-letter colon "C:\"
        std::size_t sep = std::string_view::npos;
        for (std::size_t pos = i; pos < text.size(); ++pos) {
            if (text[pos] == ';') {
                sep = pos;
                break;
            }
            if (text[pos] == ':') {
                const bool win_drive = (pos == i + 1) &&
                                       std::isalpha(static_cast<unsigned char>(text[i])) &&
                                       (pos + 1 < text.size()) &&
                                       (text[pos + 1] == '\\' || text[pos + 1] == '/');
                if (!win_drive) {
                    sep = pos;
                    break;
                }
            }
        }
        std::string_view seg = sep == std::string_view::npos ? text.substr(i) : text.substr(i, sep - i);
        while (!seg.empty() && std::isspace(static_cast<unsigned char>(seg.front()))) {
            seg.remove_prefix(1);
        }
        while (!seg.empty() && std::isspace(static_cast<unsigned char>(seg.back()))) {
            seg.remove_suffix(1);
        }
        if (!seg.empty()) {
            push_unique_path(roots, std::filesystem::path(seg));
        }
        if (sep == std::string_view::npos) {
            break;
        }
        i = sep + 1;
    }
    return roots;
}

DependencyGraph build_dependency_graph(
    const IBinaryImage& root_image,
    const DependencyResolveOptions& options,
    IProcessSession* live_session) {
    GraphBuilder builder(root_image, options, live_session);
    return builder.build();
}

Result<DependencyGraph> build_dependency_graph_from_file(
    const std::filesystem::path& binary_path,
    DependencyResolveOptions options,
    IProcessSession* live_session) {
    FileMapping<std::uint8_t, NativeFileMappingBackend> mapped;
    if (auto ec = mapped.open(binary_path.string(), MapMode::read_only); ec) {
        return make_error(std::format("Failed to open binary '{}': {}",
                                      binary_path.string(), ec.message()));
    }
    auto parsed = parse_image(mapped.view());
    if (!parsed.has_value() || !*parsed) {
        return make_error(std::format("Failed to parse binary '{}': {}",
                                      binary_path.string(),
                                      parsed.has_value() ? "null image" : parsed.error().message));
    }
    if (options.root_path.empty()) {
        options.root_path = binary_path;
    }
    return build_dependency_graph(**parsed, options, live_session);
}

} // namespace peelf
