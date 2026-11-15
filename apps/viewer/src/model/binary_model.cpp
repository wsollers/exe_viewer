#include "binary_model.hpp"
#include "pe_model.hpp"
#include "pe_parser.hpp"
#include "symbols/debug_symbols.hpp"

#include <peelf/dwarf.hpp>
#include <peelf/error.hpp>
#include <peelf/sha256.hpp>

#include <algorithm>
#include <array>
#include <cstdio>
#include <fstream>
#include <limits>
#include <utility>

namespace viewer {
namespace {
std::filesystem::path utf8_path(std::string_view text) {
    return std::filesystem::path(std::u8string(text.begin(), text.end()));
}

[[nodiscard]] std::string format_hex_addr(std::uint64_t value) {
    std::array<char, 32> buf{};
    std::snprintf(buf.data(), buf.size(), "0x%llX", static_cast<unsigned long long>(value));
    return buf.data();
}

[[nodiscard]] std::uint64_t compute_image_mapped_span(const peelf::IBinaryImage& img,
                                                      std::uint64_t base_va,
                                                      std::uint64_t min_size) {
    std::uint64_t max_end = min_size;
    for (const peelf::Section& sec : img.sections()) {
        if (sec.virtual_address >= base_va) {
            const std::uint64_t sz = std::max(sec.virtual_size, sec.file_size);
            max_end = std::max(max_end, (sec.virtual_address - base_va) + sz);
        }
    }
    for (const peelf::Segment& seg : img.segments()) {
        if (seg.virtual_address >= base_va) {
            const std::uint64_t sz = std::max(seg.virtual_size, seg.file_size);
            max_end = std::max(max_end, (seg.virtual_address - base_va) + sz);
        }
    }
    return std::max<std::uint64_t>(max_end, 4096u);
}

[[nodiscard]] bool interval_list_contains(const std::vector<peelf::PatchInterval>& list,
                                          std::uint64_t address) noexcept {
    const auto it = std::upper_bound(
        list.begin(),
        list.end(),
        address,
        [](std::uint64_t addr, const peelf::PatchInterval& iv) {
            return addr < iv.offset;
        });
    if (it == list.begin()) {
        return false;
    }
    const peelf::PatchInterval& prev = *std::prev(it);
    const auto len = static_cast<std::uint64_t>(prev.patched.size());
    return address >= prev.offset && (address - prev.offset) < len;
}

} // namespace

    void BinaryModel::reset_all() {
        ++content_generation_;
        cached_content_sha256_.clear();
        cached_sha256_generation_ = std::numeric_limits<std::uint64_t>::max();
        cached_sha256_revision_ = std::numeric_limits<std::uint64_t>::max();
        source_kind_ = BinarySourceKind::None;
        live_target_kind_ = LiveViewTargetKind::None;
        format_ = BinaryFormat::None;
        architecture_ = peelf::Architecture::Unknown;
        endianness_ = peelf::Endianness::Little;
        file_info_ = {};
        bytes_.clear();
        live_backing_file_bytes_.clear();
        live_module_snapshot_bytes_.clear();
        live_pe_backing_bytes_.clear();
        sections_.clear();
        pe_.reset();
        image_.reset();
        editable_image_.reset();
        symbol_index_ = {};
        function_index_ = {};
        analysis_thumb_mode_ = false;
        debug_symbols_by_key_.clear();
        debug_types_by_key_.clear();
        source_lines_by_key_.clear();
        auto_loaded_debug_keys_.clear();
        active_debug_types_.clear();
        active_source_lines_.clear();
        applied_structures_.clear();
        bookmarks_.clear();
        patch_metadata_by_offset_.clear();
        ++structure_binding_revision_;
        ++bookmark_revision_;
        session_.reset();
        resolved_exe_path_.reset();
        regions_.clear();
        memory_summary_ = {};
        address_space_clusters_.clear();
        modules_.clear();
        active_module_index_.reset();
        active_region_index_.reset();
        live_window_base_ = 0;
        live_window_size_ = 0;
        live_patches_.clear();
        threads_.clear();
        threads_status_ = {};
        selected_tid_.reset();
        selected_thread_context_ = {};
        selected_thread_stack_ = {};
        selected_thread_locals_ = {};
        header_flags_ = {};
        process_env_ = {};
        thread_env_ = {};
        handlers_report_ = {};
        security_audit_ = {};
        process_internals_ = {};
        process_internals_loaded_ = false;
        thread_cpu_tracker_.reset();
        last_diagnostic_.clear();
    }

    std::string BinaryModel::current_debug_symbol_key() const {
        if (is_live_process()) {
            if (const peelf::ModuleInfo* mod = active_module()) {
                if (!mod->path.empty()) {
                    return mod->path.string();
                }
                if (!mod->name.empty()) {
                    return mod->name;
                }
                return format_hex_addr(mod->base_address);
            }
        }
        return file_info_.path;
    }

    void BinaryModel::store_debug_symbol_result_for_key(const std::string& key,
                                                        const DebugSymbolLoadResult& result) {
        if (key.empty() || result.status != DebugSymbolLoadStatus::Loaded) {
            return;
        }
        if (!result.symbols.empty()) {
            const std::vector<DebugSymbol> rebased =
                (image_ != nullptr && image_->image_base() != 0)
                    ? rebase_debug_symbols(result.symbols, image_->image_base())
                    : result.symbols;
            auto& stored = debug_symbols_by_key_[key];
            stored.insert(stored.end(), rebased.begin(), rebased.end());
        }
        if (!result.types.empty()) {
            auto& stored_types = debug_types_by_key_[key];
            stored_types.insert(stored_types.end(), result.types.begin(), result.types.end());
            std::ranges::sort(stored_types, [](const DataTypeRecord& a, const DataTypeRecord& b) {
                if (a.name != b.name) return a.name < b.name;
                return a.members.size() > b.members.size();
            });
            stored_types.erase(
                std::ranges::unique(stored_types, [](const DataTypeRecord& a, const DataTypeRecord& b) {
                    return a.name == b.name && a.size == b.size;
                }).begin(),
                stored_types.end());
        }
        if (!result.lines.empty()) {
            const std::vector<SourceLineMapping> rebased_lines =
                (image_ != nullptr && image_->image_base() != 0)
                    ? rebase_source_lines(result.lines, image_->image_base())
                    : result.lines;
            auto& stored_lines = source_lines_by_key_[key];
            stored_lines.insert(stored_lines.end(), rebased_lines.begin(), rebased_lines.end());
        }
    }

    bool BinaryModel::auto_load_debug_info_for_current_image(const std::filesystem::path& image_path) {
        if (!image_) {
            return false;
        }
        const std::string key = current_debug_symbol_key();
        if (key.empty() || auto_loaded_debug_keys_.contains(key)) {
            return false;
        }
        auto_loaded_debug_keys_.insert(key);

        bool loaded_any = false;
        const auto absorb = [&](const DebugSymbolLoadResult& res) {
            if (res.status == DebugSymbolLoadStatus::Loaded &&
                (!res.symbols.empty() || !res.types.empty() || !res.lines.empty())) {
                store_debug_symbol_result_for_key(key, res);
                loaded_any = true;
            }
        };

        if (is_live_process()) {
            // Live mapped modules do not map non-SHF_ALLOC `.debug_*` or `.gnu_debuglink` sections into RAM,
            // so inspect the backing on-disk ELF/PE image when available and rebase onto `image_->image_base()`.
            std::unique_ptr<peelf::IBinaryImage> disk_image;
            if (!live_backing_file_bytes_.empty()) {
                if (auto parsed_disk = peelf::parse_image(live_backing_file_bytes_)) {
                    disk_image = std::move(*parsed_disk);
                }
            }
            const peelf::IBinaryImage& metadata_source = disk_image ? *disk_image : *image_;
            if (disk_image && peelf::has_embedded_dwarf(*disk_image)) {
                absorb(load_dwarf_debug_symbols_from_image(
                    *disk_image, live_backing_file_bytes_, *image_, image_path.string()));
            }
            if (!image_path.empty()) {
                if (const auto sidecar = find_local_elf_debug_file(metadata_source, image_path)) {
                    absorb(load_dwarf_debug_symbols(*sidecar, *image_));
                }
                if (const auto pdb = find_local_codeview_pdb(*image_, image_path)) {
                    absorb(load_pdb_debug_symbols(*pdb, *image_));
                }
            }
        } else {
            if (peelf::has_embedded_dwarf(*image_) && !bytes_.empty()) {
                absorb(load_dwarf_debug_symbols_from_image(*image_, bytes_, *image_, image_path.string()));
            }
            if (!image_path.empty()) {
                if (const auto sidecar = find_local_elf_debug_file(*image_, image_path)) {
                    absorb(load_dwarf_debug_symbols(*sidecar, *image_));
                }
            }
        }

        return loaded_any;
    }

    void BinaryModel::rebuild_symbol_index() {
        active_debug_types_.clear();
        active_source_lines_.clear();
        if (!image_) {
            symbol_index_ = {};
            function_index_ = {};
            refresh_runtime_and_handlers();
            return;
        }
        symbol_index_ = SymbolIndex::build(*image_);
        const std::string key = current_debug_symbol_key();
        if (!key.empty()) {
            const auto it = debug_symbols_by_key_.find(key);
            if (it != debug_symbols_by_key_.end() && !it->second.empty()) {
                const std::vector<DebugSymbol> rebased =
                    image_->image_base() != 0
                        ? rebase_debug_symbols(it->second, image_->image_base())
                        : it->second;
                symbol_index_.add_debug_symbols(*image_, rebased);
            }
            if (const auto tit = debug_types_by_key_.find(key); tit != debug_types_by_key_.end()) {
                active_debug_types_ = tit->second;
            }
            if (const auto lit = source_lines_by_key_.find(key); lit != source_lines_by_key_.end()) {
                active_source_lines_ =
                    image_->image_base() != 0
                        ? rebase_source_lines(lit->second, image_->image_base())
                        : lit->second;
                std::ranges::sort(active_source_lines_, [](const SourceLineMapping& a, const SourceLineMapping& b) {
                    if (a.virtual_address != b.virtual_address) {
                        return a.virtual_address < b.virtual_address;
                    }
                    return a.line < b.line;
                });
            }
        }

        function_index_ = FunctionIndex::discover(
            *image_,
            symbol_index_,
            analysis_image_bytes(),
            analysis_thumb_mode_);

        for (const FunctionEntry& fn : function_index_.entries()) {
            if (fn.virtual_address == 0) {
                continue;
            }
            const SymbolRecord* existing = symbol_index_.find_containing_address(fn.virtual_address);
            if (existing != nullptr && existing->virtual_address == fn.virtual_address) {
                continue;
            }
            SymbolRecord rec;
            rec.name = fn.name;
            rec.virtual_address = fn.virtual_address;
            rec.file_offset = fn.file_offset
                ? fn.file_offset
                : image_->virtual_address_to_file_offset(fn.virtual_address);
            rec.size = fn.size;
            rec.source = SymbolSource::DebugSymbol;
            rec.function = true;
            symbol_index_.add_discovered_symbol(std::move(rec));
        }

        refresh_runtime_and_handlers();
    }

    void BinaryModel::load_live_module_backing_bytes(const peelf::ModuleInfo& module) {
        live_backing_file_bytes_.clear();
        live_module_snapshot_bytes_.clear();

        std::filesystem::path candidate = module.path;
        std::error_code ec;
        if ((candidate.empty() || !std::filesystem::is_regular_file(candidate, ec)) &&
            module.is_main_module && resolved_exe_path_) {
            candidate = *resolved_exe_path_;
        }

        constexpr std::uintmax_t kMaxBackingBytes = 128ull * 1024ull * 1024ull;
        if (!candidate.empty() && std::filesystem::is_regular_file(candidate, ec)) {
            const auto fsize = std::filesystem::file_size(candidate, ec);
            if (!ec && fsize >= 64u && fsize <= kMaxBackingBytes) {
                std::ifstream in(candidate, std::ios::binary);
                if (in) {
                    live_backing_file_bytes_.resize(static_cast<std::size_t>(fsize));
                    if (!in.read(reinterpret_cast<char*>(live_backing_file_bytes_.data()),
                                 static_cast<std::streamsize>(live_backing_file_bytes_.size()))) {
                        live_backing_file_bytes_.clear();
                    }
                }
            }
        }

        if (live_backing_file_bytes_.empty() && session_ != nullptr && module.size != 0) {
            constexpr std::uint64_t kMaxSnapshotBytes = 16ull * 1024ull * 1024ull;
            const auto snap_sz = static_cast<std::size_t>(
                std::min<std::uint64_t>(module.size, kMaxSnapshotBytes));
            const peelf::MemorySample sample =
                peelf::read_memory_tolerant(*session_, regions_, module.base_address, snap_sz);
            if (sample.readable_count > 0) {
                live_module_snapshot_bytes_ = sample.bytes;
            }
        }
    }

    bool BinaryModel::load_file(const std::string& path) {
        std::ifstream f(utf8_path(path), std::ios::binary | std::ios::ate);
        if (!f) {
            last_diagnostic_ = "Failed to open file: " + path;
            return false;
        }

        const auto length = f.tellg();
        if (length < 0) return false;
        std::vector<std::uint8_t> loaded_bytes(static_cast<std::size_t>(length));
        f.seekg(0);
        if (!f.read(reinterpret_cast<char*>(loaded_bytes.data()), static_cast<std::streamsize>(loaded_bytes.size()))) return false;

        reset_all();
        bytes_ = std::move(loaded_bytes);

        if (bytes_.size() < 2) {
            bytes_.clear();
            last_diagnostic_ = "File is too small to be a PE or ELF image";
            return false;
        }

        // Offline crash dumps (`WU-14`: Windows `"MDMP"` .dmp and Linux ELF `ET_CORE`)
        // must be detected BEFORE `peelf::parse_image`, since `ET_CORE` begins with `\x7FELF`.
        if (peelf::is_crash_dump_bytes(bytes_)) {
            auto opened_dump = peelf::open_crash_dump_bytes(std::move(bytes_), utf8_path(path));
            if (!opened_dump.has_value()) {
                const std::string err = opened_dump.error().message;
                reset_all();
                last_diagnostic_ = err;
                return false;
            }
            auto attached = attach_session(std::move(*opened_dump));
            if (!attached.has_value()) {
                const std::string err = attached.error().message;
                reset_all();
                last_diagnostic_ = err;
                return false;
            }
            if (file_info_.path.empty() || file_info_.path.starts_with("[")) {
                file_info_.path = path;
            }
            return true;
        }

        if (auto parsed = peelf::parse_image(bytes_)) {
            image_ = std::move(*parsed);
            architecture_ = image_->architecture();
            endianness_ = image_->endianness();
        }

        // PE (MZ) -> legacy PE model, which drives the PE-specific panels.
        if (bytes_[0] == 'M' && bytes_[1] == 'Z') {
            const bool loaded = load_pe(path);
            if (loaded) {
                ++content_generation_;
                source_kind_ = BinarySourceKind::StaticFile;
                if (architecture_ == peelf::Architecture::Unknown && pe_) {
                    architecture_ = pe_->is_pe32_plus ? peelf::Architecture::X86_64
                                                      : peelf::Architecture::X86;
                }
                if (auto editable = peelf::PagedBinaryImage::open(utf8_path(path))) {
                    editable_image_ = std::move(*editable);
                }
                (void)auto_load_debug_info_for_current_image(utf8_path(path));
                rebuild_symbol_index();
            }
            return loaded;
        }

        // ELF -> identity from the unified image.
        if (image_ && image_->format() == peelf::Format::ELF) {
            const bool loaded = load_elf(path);
            if (loaded) {
                ++content_generation_;
                source_kind_ = BinarySourceKind::StaticFile;
                if (auto editable = peelf::PagedBinaryImage::open(utf8_path(path))) {
                    editable_image_ = std::move(*editable);
                }
                (void)auto_load_debug_info_for_current_image(utf8_path(path));
                rebuild_symbol_index();
            }
            return loaded;
        }

        reset_all();
        last_diagnostic_ = "Unsupported executable format: " + path;
        return false;
    }

    void BinaryModel::set_process_backend(std::shared_ptr<peelf::IProcessBackend> backend) {
        backend_ = std::move(backend);
    }

    peelf::IProcessBackend& BinaryModel::process_backend() {
        if (!backend_) {
            backend_ = peelf::create_native_process_backend();
        }
        return *backend_;
    }

    peelf::Result<std::vector<peelf::ProcessInfo>> BinaryModel::list_processes() {
        auto listed = process_backend().list_processes();
        if (!listed) {
            last_diagnostic_ = listed.error().message;
        }
        return listed;
    }

    peelf::Result<void> BinaryModel::attach_process(peelf::ProcessId pid) {
        auto opened = process_backend().open_process(pid);
        if (!opened) {
            last_diagnostic_ = opened.error().message;
            return std::unexpected(opened.error());
        }
        return attach_session(std::move(*opened));
    }

    peelf::Result<void> BinaryModel::attach_session(std::unique_ptr<peelf::IProcessSession> session) {
        if (!session) {
            last_diagnostic_ = "Process session is null";
            return peelf::make_error(last_diagnostic_);
        }

        reset_all();
        session_ = std::move(session);
        source_kind_ = BinarySourceKind::LiveProcess;
        architecture_ = session_->info().architecture != peelf::Architecture::Unknown
                            ? session_->info().architecture
                            : peelf::Architecture::X86_64;
        endianness_ = session_->info().endianness;

        std::error_code ec;
        if (!session_->info().executable_path.empty() &&
            std::filesystem::is_regular_file(session_->info().executable_path, ec)) {
            resolved_exe_path_ = session_->info().executable_path;
        } else if (!session_->info().command_line.empty()) {
            resolved_exe_path_ = peelf::resolve_executable_from_command_line(
                session_->info().command_line,
                session_->info().working_directory);
        }

        auto map_res = refresh_process_map();
        (void)refresh_threads();
        if (const peelf::CrashDumpSummary* dump = crash_dump_summary(); dump != nullptr) {
            if (dump->exception.has_value()) {
                if (dump->exception->thread_id.has_value() && *dump->exception->thread_id != 0u) {
                    for (const peelf::ThreadInfo& th : threads_) {
                        if (th.tid == *dump->exception->thread_id) {
                            select_thread(th.tid);
                            break;
                        }
                    }
                }
                if (dump->exception->instruction_pointer.has_value() &&
                    *dump->exception->instruction_pointer != 0u) {
                    (void)navigate_to_virtual_address(*dump->exception->instruction_pointer);
                }
            }
            refresh_process_internals();
        }
        refresh_runtime_and_handlers();
        return map_res;
    }

    const peelf::CrashDumpSummary* BinaryModel::crash_dump_summary() const noexcept {
        if (!is_crash_dump()) {
            return nullptr;
        }
        const auto* dump = dynamic_cast<const peelf::ICrashDumpSession*>(session_.get());
        return dump != nullptr ? &dump->crash_summary() : nullptr;
    }

    void BinaryModel::detach_process() {
        reset_all();
    }

    peelf::Result<void> BinaryModel::refresh_process_map() {
        if (!is_live_process()) {
            last_diagnostic_ = "No live process is attached";
            return peelf::make_error(last_diagnostic_);
        }
        if (!session_->is_alive()) {
            last_diagnostic_ = "Attached process PID " + std::to_string(session_->pid()) + " has exited";
            return peelf::make_error(last_diagnostic_);
        }

        if (!resolved_exe_path_ && !session_->info().command_line.empty()) {
            resolved_exe_path_ = peelf::resolve_executable_from_command_line(
                session_->info().command_line,
                session_->info().working_directory);
        }

        const std::optional<std::uint64_t> prev_mod_base =
            active_module() ? std::optional<std::uint64_t>(active_module()->base_address) : std::nullopt;
        const std::optional<std::uint64_t> prev_reg_start =
            active_region() ? std::optional<std::uint64_t>(active_region()->start_address) : std::nullopt;
        const LiveViewTargetKind prev_kind = live_target_kind_;

        auto regs = session_->memory_regions();
        if (!regs) {
            last_diagnostic_ = regs.error().message;
            return std::unexpected(regs.error());
        }
        auto mods = session_->modules();
        if (!mods) {
            last_diagnostic_ = mods.error().message;
            return std::unexpected(mods.error());
        }

        regions_ = std::move(*regs);
        modules_ = std::move(*mods);
        memory_summary_ = session_->memory_summary(regions_);
        address_space_clusters_ = peelf::build_address_space_clusters(regions_);

        // Hydrate main module backing path from command-line resolution when missing on disk.
        if (resolved_exe_path_) {
            std::error_code ec;
            bool hydrated = false;
            for (peelf::ModuleInfo& mod : modules_) {
                if (mod.is_main_module) {
                    if (mod.path.empty() || !std::filesystem::is_regular_file(mod.path, ec)) {
                        mod.path = *resolved_exe_path_;
                    }
                    if (mod.name.empty()) {
                        mod.name = mod.path.filename().string();
                    }
                    hydrated = true;
                }
            }
            if (!hydrated && modules_.empty() && !regions_.empty()) {
                for (const peelf::MemoryRegion& reg : regions_) {
                    if (reg.protection.executable || reg.kind == peelf::MemoryRegionKind::Image) {
                        modules_.push_back(peelf::ModuleInfo{
                            .name = resolved_exe_path_->filename().string(),
                            .path = *resolved_exe_path_,
                            .base_address = reg.start_address,
                            .size = reg.size(),
                            .entry_point = 0,
                            .is_main_module = true,
                        });
                        break;
                    }
                }
            }
        }

        if (prev_kind == LiveViewTargetKind::Module && prev_mod_base) {
            for (std::size_t i = 0; i < modules_.size(); ++i) {
                if (modules_[i].base_address == *prev_mod_base) {
                    return select_process_module(i);
                }
            }
            last_diagnostic_ = "Previously selected module at " + format_hex_addr(*prev_mod_base) +
                               " is no longer mapped";
        } else if (prev_kind == LiveViewTargetKind::Region && prev_reg_start) {
            for (std::size_t i = 0; i < regions_.size(); ++i) {
                if (regions_[i].start_address == *prev_reg_start) {
                    return select_memory_region(i, false);
                }
            }
            last_diagnostic_ = "Previously selected memory region at " +
                               format_hex_addr(*prev_reg_start) + " is no longer mapped";
        }

        if (!modules_.empty()) {
            std::size_t preferred_idx = 0;
            for (std::size_t i = 0; i < modules_.size(); ++i) {
                if (modules_[i].is_main_module) {
                    preferred_idx = i;
                    break;
                }
            }
            return select_process_module(preferred_idx);
        }

        if (!regions_.empty()) {
            std::size_t preferred_reg = 0;
            for (std::size_t i = 0; i < regions_.size(); ++i) {
                if (regions_[i].protection.readable) {
                    preferred_reg = i;
                    break;
                }
            }
            return select_memory_region(preferred_reg, false);
        }

        live_target_kind_ = LiveViewTargetKind::None;
        live_window_base_ = 0;
        live_window_size_ = 0;
        last_diagnostic_ = "Process exposes no accessible memory regions";
        return {};
    }

    void BinaryModel::populate_live_pe_legacy_model(const peelf::ModuleInfo& module) {
        pe_.reset();
        live_pe_backing_bytes_.clear();
        if (!session_ || !image_ || image_->format() != peelf::Format::PE) {
            return;
        }
        constexpr std::uint64_t kMaxPeLegacySample = 16ull * 1024ull * 1024ull;
        const std::size_t sample_size = static_cast<std::size_t>(
            std::min<std::uint64_t>(std::max<std::uint64_t>(module.size, 0x10000u), kMaxPeLegacySample));
        const peelf::MemorySample sample =
            peelf::read_memory_tolerant(*session_, regions_, module.base_address, sample_size);
        if (sample.readable_count < 0x100) {
            return;
        }
        live_pe_backing_bytes_ =
            peelf::normalize_mapped_pe_for_file_parsers(sample.bytes, module.base_address);
        PeModel parsed_pe;
        const PeParseResult res = PeParser::parse(live_pe_backing_bytes_, parsed_pe);
        if (res.success) {
            parsed_pe.image_base = module.base_address;
            pe_ = std::make_unique<PeModel>(std::move(parsed_pe));
        } else {
            live_pe_backing_bytes_.clear();
        }
    }

    peelf::Result<void> BinaryModel::select_process_module(std::size_t module_index) {
        if (!is_live_process()) {
            return peelf::make_error("not attached to a live process");
        }
        if (module_index >= modules_.size()) {
            return peelf::make_error("module index is out of range");
        }

        const peelf::ModuleInfo& mod = modules_[module_index];
        active_module_index_ = module_index;
        active_region_index_.reset();
        for (std::size_t i = 0; i < regions_.size(); ++i) {
            if (regions_[i].end_address > mod.base_address &&
                regions_[i].start_address < mod.base_address + std::max<std::uint64_t>(mod.size, 1u)) {
                active_region_index_ = i;
                break;
            }
        }

        live_target_kind_ = LiveViewTargetKind::Module;
        ++content_generation_;
        pe_.reset();
        image_.reset();
        sections_.clear();

        load_live_module_backing_bytes(mod);
        auto loaded = peelf::load_live_module_image(*session_, mod, regions_);
        if (loaded) {
            image_ = std::move(*loaded);
            format_ = image_->format() == peelf::Format::PE ? BinaryFormat::PE : BinaryFormat::ELF;
            architecture_ = image_->architecture();
            endianness_ = image_->endianness();
            live_window_base_ = mod.base_address;
            live_window_size_ = compute_image_mapped_span(*image_, mod.base_address, mod.size);

            if (format_ == BinaryFormat::PE) {
                populate_live_pe_legacy_model(mod);
            }

            const std::string display_path = !mod.path.empty() ? mod.path.string() : mod.name;
            file_info_.path = display_path;
            file_info_.format_str = std::string(peelf::to_string(image_->format())) +
                                    (is_crash_dump() ? " (Crash Dump)" : " (Live Read-Only)");
            file_info_.arch_str = std::string(peelf::to_string(image_->architecture()));
            file_info_.size_bytes = live_window_size_;
            file_info_.entry_point = image_->entry_point();
            file_info_.flags.clear();
            if (const auto* dump = crash_dump_summary(); dump != nullptr) {
                file_info_.flags.push_back("[CRASH DUMP] " + std::string(peelf::to_string(dump->kind)));
                if (dump->exception.has_value() && !dump->exception->description.empty()) {
                    file_info_.flags.push_back(dump->exception->description);
                }
            } else {
                file_info_.flags.push_back("Live PID " + std::to_string(session_->pid()) + " (Read-Only)");
            }
            file_info_.flags.push_back("Base " + format_hex_addr(mod.base_address));
            file_info_.flags.push_back(std::string(peelf::to_string(image_->kind())));
            file_info_.flags.push_back(image_->is_64bit() ? "64-bit" : "32-bit");
            file_info_.flags.push_back(std::string(peelf::to_string(image_->endianness())));

            for (const auto& s : image_->sections()) {
                std::uint32_t flags = 0;
                if (s.readable)   flags |= 0x4u;
                if (s.writable)   flags |= 0x2u;
                if (s.executable) flags |= 0x1u;
                sections_.push_back(SectionInfo{
                    .name = s.name,
                    .address = s.virtual_address,
                    .size = std::max(s.virtual_size, s.file_size),
                    .flags = flags,
                });
            }

            std::filesystem::path debug_probe_path = mod.path;
            if (debug_probe_path.empty() && mod.is_main_module && resolved_exe_path_) {
                debug_probe_path = *resolved_exe_path_;
            }
            (void)auto_load_debug_info_for_current_image(debug_probe_path);
            rebuild_symbol_index();
            if (selected_tid_) {
                refresh_selected_thread_inspection();
            }
            last_diagnostic_.clear();
            return {};
        }

        // Fallback when module headers cannot be parsed (e.g. unreadable pages):
        // still expose the module's virtual address window for raw inspection.
        format_ = BinaryFormat::None;
        architecture_ = session_->info().architecture != peelf::Architecture::Unknown
                            ? session_->info().architecture
                            : peelf::Architecture::X86_64;
        endianness_ = session_->info().endianness;
        live_window_base_ = mod.base_address;
        live_window_size_ = std::max<std::uint64_t>(mod.size, 4096u);
        symbol_index_ = {};
        function_index_ = {};
        refresh_runtime_and_handlers();

        file_info_.path = !mod.path.empty() ? mod.path.string() : mod.name;
        file_info_.format_str = "Raw Module (Live RAM)";
        file_info_.arch_str = std::string(peelf::to_string(architecture_));
        file_info_.size_bytes = live_window_size_;
        file_info_.entry_point = mod.base_address;
        file_info_.flags = {
            "Live PID " + std::to_string(session_->pid()),
            "Base " + format_hex_addr(mod.base_address),
            "Unparsed headers: " + loaded.error().message,
        };
        last_diagnostic_ = loaded.error().message;
        return {};
    }

    peelf::Result<void> BinaryModel::select_memory_region(std::size_t region_index,
                                                          bool prefer_module_context) {
        if (!is_live_process()) {
            return peelf::make_error("not attached to a live process");
        }
        if (region_index >= regions_.size()) {
            return peelf::make_error("memory region index is out of range");
        }

        const peelf::MemoryRegion& reg = regions_[region_index];
        if (prefer_module_context) {
            for (std::size_t i = 0; i < modules_.size(); ++i) {
                const peelf::ModuleInfo& mod = modules_[i];
                if (reg.start_address >= mod.base_address &&
                    reg.start_address < mod.base_address + mod.size) {
                    if (active_module_index_ != i || live_target_kind_ != LiveViewTargetKind::Module) {
                        auto res = select_process_module(i);
                        if (!res) {
                            return res;
                        }
                    }
                    active_region_index_ = region_index;
                    return {};
                }
            }
        }

        active_module_index_.reset();
        active_region_index_ = region_index;
        live_target_kind_ = LiveViewTargetKind::Region;
        ++content_generation_;
        live_window_base_ = reg.start_address;
        live_window_size_ = reg.size();

        pe_.reset();
        image_.reset();
        live_backing_file_bytes_.clear();
        live_module_snapshot_bytes_.clear();
        sections_.clear();
        symbol_index_ = {};
        function_index_ = {};
        format_ = BinaryFormat::None;
        architecture_ = session_->info().architecture != peelf::Architecture::Unknown
                            ? session_->info().architecture
                            : peelf::Architecture::X86_64;
        endianness_ = session_->info().endianness;

        // If this standalone region starts with an in-RAM PE or ELF header (e.g. [vdso]
        // or manually mapped module), parse it opportunistically.
        if (reg.protection.readable && reg.size() >= 64) {
            const auto probe_sz = static_cast<std::size_t>(
                std::min<std::uint64_t>(reg.size(), 4ull * 1024ull * 1024ull));
            const peelf::MemorySample sample =
                peelf::read_memory_tolerant(*session_, regions_, reg.start_address, probe_sz);
            if (sample.readable_count > 0) {
                live_module_snapshot_bytes_ = sample.bytes;
            }
            if (sample.readable_count >= 64) {
                const bool looks_pe_or_elf =
                    (sample.bytes[0] == 0x7Fu && sample.bytes[1] == 'E' &&
                     sample.bytes[2] == 'L' && sample.bytes[3] == 'F') ||
                    (sample.bytes[0] == 'M' && sample.bytes[1] == 'Z');
                if (looks_pe_or_elf) {
                    if (auto mapped = peelf::parse_mapped_image(sample.bytes, reg.start_address)) {
                        image_ = std::move(*mapped);
                        format_ = image_->format() == peelf::Format::PE ? BinaryFormat::PE
                                                                        : BinaryFormat::ELF;
                        architecture_ = image_->architecture();
                        endianness_ = image_->endianness();
                        rebuild_symbol_index();
                    }
                }
            }
        }
        if (!image_) {
            refresh_runtime_and_handlers();
        }

        const std::string region_name = !reg.pathname.empty()
            ? reg.pathname
            : ("[" + std::string(peelf::to_string(reg.kind)) + "]");
        const char* mode_tag = is_crash_dump() ? "Crash Dump" : "Live RAM";
        file_info_.path = region_name;
        file_info_.format_str = image_
            ? (std::string(peelf::to_string(image_->format())) + " Region (" + mode_tag + ")")
            : (std::string("Memory Region (") + mode_tag + ")");
        file_info_.arch_str = std::string(peelf::to_string(architecture_));
        file_info_.size_bytes = reg.size();
        file_info_.entry_point = image_ ? image_->entry_point() : reg.start_address;
        file_info_.flags = {
            (is_crash_dump() ? "[CRASH DUMP] PID " : "Live PID ") + std::to_string(session_->pid()),
            "Range " + format_hex_addr(reg.start_address) + " - " + format_hex_addr(reg.end_address),
            "Perms " + peelf::format_protection(reg.protection),
            "Kind " + std::string(peelf::to_string(reg.kind)),
        };
        if (const auto* dump = crash_dump_summary(); dump != nullptr && dump->exception.has_value()) {
            file_info_.flags.push_back(dump->exception->description);
        }

        std::uint32_t flags = 0;
        if (reg.protection.readable)   flags |= 0x4u;
        if (reg.protection.writable)   flags |= 0x2u;
        if (reg.protection.executable) flags |= 0x1u;
        sections_.push_back(SectionInfo{
            .name = region_name,
            .address = reg.start_address,
            .size = reg.size(),
            .flags = flags,
        });

        last_diagnostic_.clear();
        return {};
    }

    std::optional<std::uint64_t> BinaryModel::navigate_to_virtual_address(std::uint64_t virtual_address) {
        if (!is_live_process()) {
            return virtual_address_to_offset(virtual_address);
        }
        if (const auto off = virtual_address_to_offset(virtual_address)) {
            return off;
        }

        for (std::size_t i = 0; i < modules_.size(); ++i) {
            const peelf::ModuleInfo& mod = modules_[i];
            if (virtual_address >= mod.base_address &&
                virtual_address < mod.base_address + mod.size) {
                if (select_process_module(i)) {
                    return virtual_address_to_offset(virtual_address);
                }
            }
        }

        for (std::size_t i = 0; i < regions_.size(); ++i) {
            const peelf::MemoryRegion& reg = regions_[i];
            if (reg.contains(virtual_address)) {
                if (select_memory_region(i, false)) {
                    return virtual_address_to_offset(virtual_address);
                }
            }
        }
        return std::nullopt;
    }

    const peelf::ModuleInfo* BinaryModel::active_module() const noexcept {
        if (!active_module_index_ || *active_module_index_ >= modules_.size()) {
            return nullptr;
        }
        return &modules_[*active_module_index_];
    }

    const peelf::MemoryRegion* BinaryModel::active_region() const noexcept {
        if (!active_region_index_ || *active_region_index_ >= regions_.size()) {
            return nullptr;
        }
        return &regions_[*active_region_index_];
    }

    peelf::TargetLayout BinaryModel::target_layout() const noexcept {
        if (image_ != nullptr) {
            return peelf::TargetLayout::from_image(*image_);
        }
        const bool is_32bit =
            architecture_ == peelf::Architecture::X86 ||
            architecture_ == peelf::Architecture::ARM ||
            architecture_ == peelf::Architecture::RISCV32 ||
            architecture_ == peelf::Architecture::PowerPC ||
            architecture_ == peelf::Architecture::MIPS32;
        return peelf::TargetLayout::from_arch(architecture_, !is_32bit, endianness_);
    }

    std::span<const std::uint8_t> BinaryModel::analysis_image_bytes() const noexcept {
        if (!is_live_process()) {
            return bytes_;
        }
        if (!live_backing_file_bytes_.empty()) {
            return live_backing_file_bytes_;
        }
        return live_module_snapshot_bytes_;
    }

    std::uint64_t BinaryModel::analysis_image_size() const noexcept {
        if (!is_live_process()) {
            return view_size();
        }
        const auto backing = static_cast<std::uint64_t>(analysis_image_bytes().size());
        return std::max(view_size(), backing);
    }

    void BinaryModel::set_analysis_thumb_mode(bool thumb_mode) {
        if (analysis_thumb_mode_ == thumb_mode) {
            return;
        }
        analysis_thumb_mode_ = thumb_mode;
        if (image_ != nullptr) {
            rebuild_symbol_index();
        }
    }

    std::string BinaryModel::resolve_address_symbol(std::uint64_t virtual_address) const {
        if (virtual_address == 0) {
            return {};
        }

        std::string module_prefix;
        if (is_live_process()) {
            if (const peelf::ModuleInfo* act = active_module()) {
                if (virtual_address >= act->base_address &&
                    virtual_address < act->base_address + std::max<std::uint64_t>(act->size, live_window_size_)) {
                    module_prefix = !act->name.empty() ? act->name : act->path.filename().string();
                }
            }
        }

        if (const SymbolRecord* sym = symbol_index_.find_containing_address(virtual_address);
            sym != nullptr && sym->virtual_address.has_value()) {
            const std::uint64_t delta = virtual_address - *sym->virtual_address;
            const std::uint64_t limit = sym->size != 0 ? sym->size : 0x4000u;
            if (delta == 0 || delta < limit) {
                const std::string& sname = sym->display_name(demangle_symbols_);
                std::string label = module_prefix.empty() ? sname : (module_prefix + "!" + sname);
                if (delta != 0) {
                    label += "+" + format_hex_addr(delta);
                }
                return label;
            }
        }

        if (is_live_process()) {
            for (const peelf::ModuleInfo& mod : modules_) {
                if (virtual_address >= mod.base_address &&
                    virtual_address < mod.base_address + std::max<std::uint64_t>(mod.size, 1u)) {
                    const std::string mname = !mod.name.empty()
                        ? mod.name
                        : (!mod.path.empty() ? mod.path.filename().string() : "module");
                    const std::uint64_t rva = virtual_address - mod.base_address;
                    return rva == 0 ? mname : (mname + "+" + format_hex_addr(rva));
                }
            }
        }

        return {};
    }

    void BinaryModel::add_debug_symbols(std::span<const DebugSymbol> symbols) {
        if (!image_ || symbols.empty()) {
            return;
        }
        const std::vector<DebugSymbol> rebased =
            image_->image_base() != 0
                ? rebase_debug_symbols(symbols, image_->image_base())
                : std::vector<DebugSymbol>(symbols.begin(), symbols.end());

        const std::string key = current_debug_symbol_key();
        if (!key.empty()) {
            auto& stored = debug_symbols_by_key_[key];
            stored.insert(stored.end(), rebased.begin(), rebased.end());
        }
        rebuild_symbol_index();
    }

    void BinaryModel::apply_debug_symbol_result(const DebugSymbolLoadResult& result) {
        if (!image_ || result.status != DebugSymbolLoadStatus::Loaded) {
            return;
        }
        const std::string key = current_debug_symbol_key();
        if (!key.empty()) {
            store_debug_symbol_result_for_key(key, result);
        }
        rebuild_symbol_index();
    }

    const SourceLineMapping* BinaryModel::find_source_line(std::uint64_t virtual_address,
                                                           std::uint64_t max_distance) const noexcept {
        if (active_source_lines_.empty() || virtual_address == 0) {
            return nullptr;
        }
        const auto upper = std::upper_bound(
            active_source_lines_.begin(),
            active_source_lines_.end(),
            virtual_address,
            [](std::uint64_t addr, const SourceLineMapping& entry) {
                return addr < entry.virtual_address;
            });
        if (upper == active_source_lines_.begin()) {
            return nullptr;
        }
        const SourceLineMapping& candidate = *std::prev(upper);
        const std::uint64_t delta = virtual_address - candidate.virtual_address;
        if (delta > max_distance) {
            return nullptr;
        }
        return &candidate;
    }

    void BinaryModel::add_applied_structure(AppliedStructureBinding binding) {
        if (binding.type_name.empty()) {
            return;
        }
        if (binding.count == 0) {
            binding.count = 1;
        }
        for (AppliedStructureBinding& existing : applied_structures_) {
            if (existing.address == binding.address &&
                existing.is_file_offset == binding.is_file_offset &&
                existing.type_name == binding.type_name) {
                existing.count = binding.count;
                if (!binding.label.empty()) {
                    existing.label = std::move(binding.label);
                }
                ++structure_binding_revision_;
                return;
            }
        }
        applied_structures_.push_back(std::move(binding));
        ++structure_binding_revision_;
    }

    void BinaryModel::remove_applied_structure(std::size_t index) {
        if (index < applied_structures_.size()) {
            applied_structures_.erase(applied_structures_.begin() + static_cast<std::ptrdiff_t>(index));
            ++structure_binding_revision_;
        }
    }

    void BinaryModel::add_or_update_bookmark(Bookmark bookmark) {
        for (Bookmark& existing : bookmarks_) {
            if (existing.address == bookmark.address &&
                existing.is_file_offset == bookmark.is_file_offset) {
                existing = std::move(bookmark);
                ++bookmark_revision_;
                return;
            }
        }
        const auto pos = std::ranges::lower_bound(
            bookmarks_,
            bookmark,
            [](const Bookmark& lhs, const Bookmark& rhs) {
                if (lhs.is_file_offset != rhs.is_file_offset) {
                    return lhs.is_file_offset < rhs.is_file_offset;
                }
                return lhs.address < rhs.address;
            });
        bookmarks_.insert(pos, std::move(bookmark));
        ++bookmark_revision_;
    }

    bool BinaryModel::remove_bookmark_at(std::uint64_t address, bool is_file_offset) {
        const auto it = std::ranges::find_if(bookmarks_, [&](const Bookmark& bm) {
            return bm.address == address && bm.is_file_offset == is_file_offset;
        });
        if (it == bookmarks_.end()) {
            return false;
        }
        bookmarks_.erase(it);
        ++bookmark_revision_;
        return true;
    }

    void BinaryModel::remove_bookmark_index(std::size_t index) {
        if (index < bookmarks_.size()) {
            bookmarks_.erase(bookmarks_.begin() + static_cast<std::ptrdiff_t>(index));
            ++bookmark_revision_;
        }
    }

    const Bookmark* BinaryModel::find_bookmark(std::uint64_t address,
                                               bool is_file_offset) const noexcept {
        const auto it = std::ranges::find_if(bookmarks_, [&](const Bookmark& bm) {
            return bm.address == address && bm.is_file_offset == is_file_offset;
        });
        return it != bookmarks_.end() ? &*it : nullptr;
    }

    std::uint64_t BinaryModel::view_base_address() const noexcept {
        return is_live_process() ? live_window_base_ : 0u;
    }

    std::uint64_t BinaryModel::view_size() const noexcept {
        if (is_live_process()) {
            return live_window_size_;
        }
        if (editable_image_) {
            return editable_image_->size();
        }
        return static_cast<std::uint64_t>(bytes_.size());
    }

    std::optional<std::uint64_t> BinaryModel::offset_to_virtual_address(std::uint64_t offset) const noexcept {
        if (is_live_process()) {
            if (offset >= live_window_size_ ||
                offset > std::numeric_limits<std::uint64_t>::max() - live_window_base_) {
                return std::nullopt;
            }
            return live_window_base_ + offset;
        }
        if (image_) {
            return image_->file_offset_to_virtual_address(offset);
        }
        return std::nullopt;
    }

    std::optional<std::uint64_t> BinaryModel::virtual_address_to_offset(
        std::uint64_t virtual_address) const noexcept {
        if (is_live_process()) {
            if (virtual_address >= live_window_base_ &&
                (virtual_address - live_window_base_) < live_window_size_) {
                return virtual_address - live_window_base_;
            }
            return std::nullopt;
        }
        if (image_) {
            return image_->virtual_address_to_file_offset(virtual_address);
        }
        return std::nullopt;
    }

    bool BinaryModel::load_pe(const std::string& path) {
        PeModel pe_model;
        PeParseResult result = PeParser::parse(bytes_, pe_model);
        if (!result.success) {
            format_ = BinaryFormat::None;
            pe_.reset();
            sections_.clear();
            return false;
        }

        format_ = BinaryFormat::PE;
        pe_ = std::make_unique<PeModel>(std::move(pe_model));
        // The legacy model borrows storage owned by this BinaryModel.
        pe_->raw_data = bytes_.data();
        pe_->raw_size = bytes_.size();

        file_info_.path = path;
        file_info_.format_str = "PE";
        file_info_.arch_str = image_ ? std::string(peelf::to_string(image_->architecture())) : "Unknown";
        file_info_.size_bytes = bytes_.size();
        file_info_.entry_point = image_ ? image_->entry_point() : result.entry_point_va;
        file_info_.flags = result.flags;

        sections_.clear();
        for (const auto& s : pe_->sections) {
            sections_.push_back(SectionInfo{
                .name = s.name,
                .address = result.image_base + s.virtual_address,
                .size = s.virtual_size,
                .flags = s.characteristics
            });
        }

        return true;
    }

    bool BinaryModel::load_elf(const std::string& path) {
        if (!image_ || image_->format() != peelf::Format::ELF) {
            return false;
        }

        format_ = BinaryFormat::ELF;

        file_info_.path = path;
        file_info_.format_str = std::string(peelf::to_string(image_->format()));
        file_info_.arch_str = std::string(peelf::to_string(image_->architecture()));
        file_info_.size_bytes = bytes_.size();
        file_info_.entry_point = image_->entry_point();

        file_info_.flags.clear();
        file_info_.flags.push_back(std::string(peelf::to_string(image_->kind())));
        file_info_.flags.push_back(image_->is_64bit() ? "64-bit" : "32-bit");
        file_info_.flags.push_back(std::string(peelf::to_string(image_->endianness())));

        sections_.clear();
        for (const auto& s : image_->sections()) {
            std::uint32_t flags = 0;
            if (s.readable)   flags |= 0x4;
            if (s.writable)   flags |= 0x2;
            if (s.executable) flags |= 0x1;
            sections_.push_back(SectionInfo{
                .name = s.name,
                .address = s.virtual_address,
                .size = s.virtual_size,
                .flags = flags
            });
        }

        return true;
    }

    peelf::Result<peelf::MemorySample> BinaryModel::read_window_sample(std::uint64_t offset,
                                                                       std::uint64_t size) const {
        if (is_live_process()) {
            if (offset > live_window_size_ || size > live_window_size_ - offset) {
                return peelf::make_error("read window range exceeds active live view");
            }
            if (size > static_cast<std::uint64_t>(std::numeric_limits<std::size_t>::max())) {
                return peelf::make_error("read window size exceeds platform limit");
            }
            const std::uint64_t va = live_window_base_ + offset;
            return peelf::read_memory_tolerant(
                *session_, regions_, va, static_cast<std::size_t>(size));
        }

        if (editable_image_) {
            auto effective = editable_image_->read_effective(offset, size);
            if (!effective) {
                return std::unexpected(effective.error());
            }
            peelf::MemorySample sample;
            sample.readable_count = effective->size();
            sample.bytes = std::move(*effective);
            sample.valid.assign(sample.bytes.size(), 1u);
            return sample;
        }

        if (!bytes_.empty()) {
            if (offset > bytes_.size() || size > bytes_.size() - offset) {
                return peelf::make_error("read range exceeds loaded buffer");
            }
            peelf::MemorySample sample;
            sample.readable_count = static_cast<std::size_t>(size);
            sample.bytes.assign(bytes_.begin() + static_cast<std::ptrdiff_t>(offset),
                                bytes_.begin() + static_cast<std::ptrdiff_t>(offset + size));
            sample.valid.assign(sample.bytes.size(), 1u);
            return sample;
        }

        return peelf::make_error("no binary image or live process is loaded");
    }

    peelf::Result<std::vector<std::uint8_t>> BinaryModel::read_effective_bytes(std::uint64_t offset,
                                                                               std::uint64_t size) const {
        if (is_live_process()) {
            auto sample = read_window_sample(offset, size);
            if (!sample) {
                return std::unexpected(sample.error());
            }
            if (size != 0 && sample->readable_count == 0) {
                return peelf::make_error("live memory range is unmapped or unreadable");
            }
            return std::move(sample->bytes);
        }

        if (!editable_image_) {
            if (!bytes_.empty()) {
                if (offset > bytes_.size() || size > bytes_.size() - offset) {
                    return peelf::make_error("read range exceeds loaded buffer");
                }
                return std::vector<std::uint8_t>(
                    bytes_.begin() + static_cast<std::ptrdiff_t>(offset),
                    bytes_.begin() + static_cast<std::ptrdiff_t>(offset + size));
            }
            return peelf::make_error("no editable binary image is loaded");
        }
        return editable_image_->read_effective(offset, size);
    }

    peelf::Result<std::vector<std::uint8_t>> BinaryModel::read_virtual_bytes(
        std::uint64_t virtual_address,
        std::uint64_t size) const {
        if (size > static_cast<std::uint64_t>(std::numeric_limits<std::size_t>::max())) {
            return peelf::make_error("requested byte count exceeds platform limit");
        }
        if (is_live_process()) {
            const peelf::MemorySample sample = peelf::read_memory_tolerant(
                *session_, regions_, virtual_address, static_cast<std::size_t>(size));
            if (size != 0 && sample.readable_count == 0) {
                return peelf::make_error("live virtual address range is unreadable");
            }
            return sample.bytes;
        }
        if (image_ != nullptr) {
            const auto file_off = image_->virtual_address_to_file_offset(virtual_address);
            if (!file_off) {
                return peelf::make_error("virtual address does not map to file bytes");
            }
            return read_effective_bytes(*file_off, size);
        }
        return peelf::make_error("no binary image or live process is loaded");
    }

    peelf::Result<void> BinaryModel::apply_patch_bytes(std::uint64_t offset,
                                                       std::span<const std::uint8_t> bytes,
                                                       std::string label) {
        if (is_live_process()) {
            last_diagnostic_ = "Live process inspection is strictly read-only; target memory is never modified";
            return peelf::make_error(last_diagnostic_);
        }

        if (!editable_image_) {
            return peelf::make_error("no editable binary image is loaded");
        }
        auto result = editable_image_->apply_patch(offset, bytes, std::move(label));
        if (result) ++edit_revision_;
        return result;
    }

    peelf::Result<void> BinaryModel::apply_patch_set(std::span<const peelf::PatchInterval> patches) {
        if (is_live_process()) {
            return peelf::make_error("Live process inspection is strictly read-only");
        }
        if (!editable_image_) return peelf::make_error("No image loaded");
        if (patches.empty()) return {};
        auto transaction = editable_image_->begin_transaction("Restore project patches");
        for (const auto& patch : patches) {
            auto written = transaction.write(patch.offset, patch.patched);
            if (!written) return written;
        }
        auto result = transaction.commit();
        if (result) ++edit_revision_;
        return result;
    }

    void BinaryModel::record_patch_metadata(std::uint64_t offset,
                                            std::string label,
                                            std::optional<std::string> asm_source) {
        if (is_live_process()) {
            return;
        }
        patch_metadata_by_offset_[offset] = PatchEntryMetadata{
            .label = std::move(label),
            .asm_source = std::move(asm_source),
        };
    }

    peelf::Result<peelf::PatchBundle> BinaryModel::export_patch_bundle(
        std::string name,
        std::string description) const {
        if (is_live_process()) {
            return peelf::make_error(
                "Live process inspection is strictly read-only; patch bundles can only be exported from static files");
        }
        if (!editable_image_) {
            return peelf::make_error("No editable static binary image is loaded");
        }
        auto bundle_res = peelf::export_patch_bundle_from_image(
            *editable_image_, image_.get(), std::move(name), std::move(description));
        if (!bundle_res.has_value()) {
            return bundle_res;
        }
        for (peelf::PatchBundleEntry& entry : bundle_res->entries) {
            if (const auto it = patch_metadata_by_offset_.find(entry.offset);
                it != patch_metadata_by_offset_.end()) {
                if (!it->second.label.empty()) {
                    entry.label = it->second.label;
                }
                if (it->second.asm_source.has_value()) {
                    entry.asm_source = it->second.asm_source;
                }
            }
        }
        return bundle_res;
    }

    peelf::Result<peelf::PatchBundlePreview> BinaryModel::preview_patch_bundle(
        const peelf::PatchBundle& bundle,
        const peelf::PatchBundleApplyOptions& options) const {
        if (is_live_process()) {
            return peelf::make_error(
                "Live process inspection is strictly read-only; patch bundles cannot be previewed or applied to live memory");
        }
        if (!editable_image_) {
            return peelf::make_error("No editable static binary image is loaded");
        }
        return peelf::preview_patch_bundle(bundle, *editable_image_, options, nullptr);
    }

    peelf::Result<void> BinaryModel::apply_patch_bundle(
        const peelf::PatchBundle& bundle,
        const peelf::PatchBundleApplyOptions& options) {
        if (is_live_process()) {
            last_diagnostic_ =
                "Live process inspection is strictly read-only; patch bundles cannot be applied to live memory";
            return peelf::make_error(last_diagnostic_);
        }
        if (!editable_image_) {
            return peelf::make_error("No editable static binary image is loaded");
        }
        auto applied = peelf::apply_patch_bundle(bundle, *editable_image_, options, nullptr);
        if (applied.has_value()) {
            for (const peelf::PatchBundleEntry& entry : bundle.entries) {
                patch_metadata_by_offset_[entry.offset] = PatchEntryMetadata{
                    .label = entry.label,
                    .asm_source = entry.asm_source,
                };
            }
            ++edit_revision_;
        }
        return applied;
    }

    peelf::Result<void> BinaryModel::stage_patch_at_va(std::uint64_t /*virtual_address*/,
                                                       std::span<const std::uint8_t> /*bytes*/,
                                                       std::string /*label*/) {
        last_diagnostic_ = "Live process inspection is strictly read-only; target memory is never modified";
        return peelf::make_error(last_diagnostic_);
    }

    peelf::Result<void> BinaryModel::undo_patch() {
        if (is_live_process()) {
            return peelf::make_error("Live process inspection is strictly read-only");
        }
        if (!editable_image_) {
            return peelf::make_error("no editable binary image is loaded");
        }
        auto result = editable_image_->undo();
        if (result) ++edit_revision_;
        return result;
    }

    peelf::Result<void> BinaryModel::redo_patch() {
        if (is_live_process()) {
            return peelf::make_error("Live process inspection is strictly read-only");
        }
        if (!editable_image_) {
            return peelf::make_error("no editable binary image is loaded");
        }
        auto result = editable_image_->redo();
        if (result) ++edit_revision_;
        return result;
    }

    void BinaryModel::discard_staged_patches() noexcept {
        live_patches_.clear_staged();
    }

    peelf::Result<std::size_t> BinaryModel::commit_patches_to_process(
        peelf::MemoryWriteOptions /*options*/) {
        last_diagnostic_ = "Live process inspection is strictly read-only; committing patches to RAM is disabled";
        return peelf::make_error(last_diagnostic_);
    }

    peelf::Result<std::size_t> BinaryModel::revert_committed_patches(
        peelf::MemoryWriteOptions /*options*/) {
        last_diagnostic_ = "Live process inspection is strictly read-only";
        return peelf::make_error(last_diagnostic_);
    }

    peelf::Result<void> BinaryModel::revert_committed_patch_at(
        std::uint64_t /*virtual_address*/,
        std::uint64_t /*size*/,
        peelf::MemoryWriteOptions /*options*/) {
        last_diagnostic_ = "Live process inspection is strictly read-only";
        return peelf::make_error(last_diagnostic_);
    }

    peelf::Result<void> BinaryModel::save_patched_as(const std::filesystem::path& output_path,
                                                     bool overwrite) const {
        if (!editable_image_) {
            return peelf::make_error("no editable static binary image is loaded");
        }
        return editable_image_->write_effective_to(output_path, overwrite);
    }

    std::vector<peelf::PatchInterval> BinaryModel::changed_intervals() const {
        if (is_live_process()) {
            std::vector<peelf::PatchInterval> window_patches;
            for (peelf::PatchInterval iv : live_patches_.staged_intervals()) {
                if (iv.offset >= live_window_base_ &&
                    (iv.offset - live_window_base_) < live_window_size_) {
                    iv.offset -= live_window_base_;
                    window_patches.push_back(std::move(iv));
                }
            }
            return window_patches;
        }
        if (!editable_image_) {
            return {};
        }
        return editable_image_->changed_intervals();
    }

    std::vector<peelf::PatchInterval> BinaryModel::staged_live_patches() const {
        if (!is_live_process()) {
            return {};
        }
        return live_patches_.staged_intervals();
    }

    std::vector<peelf::PatchInterval> BinaryModel::committed_live_patches() const {
        if (!is_live_process()) {
            return {};
        }
        std::vector<peelf::PatchInterval> out;
        const auto committed = live_patches_.committed_intervals();
        out.reserve(committed.size());
        for (const peelf::CommittedPatchInterval& ci : committed) {
            out.push_back(peelf::PatchInterval{
                .offset = ci.address,
                .original = ci.original,
                .patched = ci.committed,
            });
        }
        return out;
    }

    BytePatchState BinaryModel::byte_patch_state_at_offset(std::uint64_t offset) const noexcept {
        if (is_live_process()) {
            if (offset >= live_window_size_) {
                return BytePatchState::Unchanged;
            }
            const std::uint64_t va = live_window_base_ + offset;
            const auto staged = live_patches_.staged_intervals();
            if (interval_list_contains(staged, va)) {
                return BytePatchState::Staged;
            }
            for (const peelf::CommittedPatchInterval& ci : live_patches_.committed_intervals()) {
                const auto len = static_cast<std::uint64_t>(ci.committed.size());
                if (va >= ci.address && (va - ci.address) < len) {
                    return BytePatchState::Committed;
                }
            }
            return BytePatchState::Unchanged;
        }

        if (editable_image_) {
            const auto staged = editable_image_->changed_intervals();
            if (interval_list_contains(staged, offset)) {
                return BytePatchState::Staged;
            }
        }
        return BytePatchState::Unchanged;
    }

    const std::string& BinaryModel::content_sha256() const {
        if (cached_sha256_generation_ == content_generation_ &&
            cached_sha256_revision_ == edit_revision_) {
            return cached_content_sha256_;
        }

        cached_sha256_generation_ = content_generation_;
        cached_sha256_revision_ = edit_revision_;
        cached_content_sha256_.clear();

        if (!has_file()) {
            return cached_content_sha256_;
        }

        if (!is_live_process()) {
            if (!editable_image_ || editable_image_->changed_intervals().empty()) {
                cached_content_sha256_ = peelf::sha256_hex(bytes_);
                return cached_content_sha256_;
            }

            peelf::Sha256Hasher hasher;
            constexpr std::uint64_t kChunkSize = 64ull * 1024ull;
            const auto total = static_cast<std::uint64_t>(bytes_.size());
            for (std::uint64_t offset = 0; offset < total; offset += kChunkSize) {
                const std::uint64_t len = std::min(kChunkSize, total - offset);
                if (auto chunk = read_effective_bytes(offset, len)) {
                    hasher.update(*chunk);
                } else {
                    const auto start = static_cast<std::size_t>(offset);
                    const auto count = static_cast<std::size_t>(len);
                    hasher.update(std::span<const std::uint8_t>(bytes_).subspan(start, count));
                }
            }
            cached_content_sha256_ = hasher.finalize_hex();
            return cached_content_sha256_;
        }

        peelf::Sha256Hasher hasher;
        const std::uint64_t pid = session_ ? session_->pid() : 0u;
        hasher.update(std::span<const std::uint8_t>(
            reinterpret_cast<const std::uint8_t*>(&pid), sizeof(pid)));
        hasher.update(std::span<const std::uint8_t>(
            reinterpret_cast<const std::uint8_t*>(&live_window_base_), sizeof(live_window_base_)));
        hasher.update(std::span<const std::uint8_t>(
            reinterpret_cast<const std::uint8_t*>(&live_window_size_), sizeof(live_window_size_)));

        const std::span<const std::uint8_t> analysis_bytes = analysis_image_bytes();
        if (!analysis_bytes.empty()) {
            hasher.update(analysis_bytes);
        } else if (live_window_size_ > 0) {
            const std::uint64_t probe = std::min<std::uint64_t>(live_window_size_, 64ull * 1024ull);
            if (auto sample = read_window_sample(0, probe)) {
                hasher.update(sample->bytes);
            }
        }
        cached_content_sha256_ = hasher.finalize_hex();
        return cached_content_sha256_;
    }

    bool BinaryModel::is_process_suspended() const noexcept {
        return is_live_process() && session_->is_suspended();
    }

    peelf::SubsystemStatus BinaryModel::suspend_process() {
        if (!is_live_process()) {
            return peelf::SubsystemStatus::unavailable("process", "Not attached to a live process");
        }
        auto res = session_->suspend();
        const peelf::SubsystemStatus st = res
            ? peelf::SubsystemStatus::available("process", "Process suspended")
            : peelf::SubsystemStatus::unavailable("process", res.error().message);
        if (!st.ok() && !st.detail.empty()) {
            last_diagnostic_ = st.detail;
        }
        (void)refresh_threads();
        refresh_runtime_and_handlers();
        return st;
    }

    peelf::SubsystemStatus BinaryModel::resume_process() {
        if (!is_live_process()) {
            return peelf::SubsystemStatus::unavailable("process", "Not attached to a live process");
        }
        auto res = session_->resume();
        const peelf::SubsystemStatus st = res
            ? peelf::SubsystemStatus::available("process", "Process resumed")
            : peelf::SubsystemStatus::unavailable("process", res.error().message);
        if (!st.ok() && !st.detail.empty()) {
            last_diagnostic_ = st.detail;
        }
        (void)refresh_threads();
        refresh_runtime_and_handlers();
        return st;
    }

    peelf::SubsystemStatus BinaryModel::suspend_thread(peelf::ThreadId tid) {
        if (!is_live_process()) {
            return peelf::SubsystemStatus::unavailable("thread", "Not attached to a live process");
        }
        auto res = session_->suspend_thread(tid);
        const peelf::SubsystemStatus st = res
            ? peelf::SubsystemStatus::available("thread", "Thread suspended")
            : peelf::SubsystemStatus::unavailable("thread", res.error().message);
        (void)refresh_threads();
        return st;
    }

    peelf::SubsystemStatus BinaryModel::resume_thread(peelf::ThreadId tid) {
        if (!is_live_process()) {
            return peelf::SubsystemStatus::unavailable("thread", "Not attached to a live process");
        }
        auto res = session_->resume_thread(tid);
        const peelf::SubsystemStatus st = res
            ? peelf::SubsystemStatus::available("thread", "Thread resumed")
            : peelf::SubsystemStatus::unavailable("thread", res.error().message);
        (void)refresh_threads();
        return st;
    }

    peelf::ForgivingValue<std::vector<peelf::ThreadInfo>> BinaryModel::refresh_threads() {
        if (!is_live_process()) {
            threads_.clear();
            threads_status_ = peelf::SubsystemStatus::unavailable("process", "Not attached to a live process");
            selected_tid_.reset();
            selected_thread_context_ = {};
            selected_thread_stack_ = {};
            selected_thread_locals_ = {};
            thread_env_ = {};
            return peelf::ForgivingValue<std::vector<peelf::ThreadInfo>>{
                .value = std::nullopt,
                .status = threads_status_,
            };
        }

        auto listed = session_->threads();
        if (!listed) {
            threads_.clear();
            threads_status_ = peelf::SubsystemStatus::unavailable("process", listed.error().message);
            selected_tid_.reset();
            selected_thread_context_ = {};
            selected_thread_stack_ = {};
            selected_thread_locals_ = {};
            thread_env_ = {};
            return peelf::ForgivingValue<std::vector<peelf::ThreadInfo>>{
                .value = std::nullopt,
                .status = threads_status_,
            };
        }

        threads_ = std::move(*listed);
        thread_cpu_tracker_.update(threads_);
        threads_status_ = peelf::SubsystemStatus::available(
            "process",
            std::to_string(threads_.size()) + " thread(s) discovered");

        bool keep_selected = false;
        if (selected_tid_) {
            for (const peelf::ThreadInfo& th : threads_) {
                if (th.tid == *selected_tid_) {
                    keep_selected = true;
                    break;
                }
            }
        }
        if (!keep_selected) {
            if (!threads_.empty()) {
                selected_tid_ = threads_.front().tid;
            } else {
                selected_tid_.reset();
            }
        }

        if (selected_tid_) {
            refresh_selected_thread_inspection();
        } else {
            selected_thread_context_ = {};
            selected_thread_stack_ = {};
            selected_thread_locals_ = {};
            thread_env_ = {};
        }

        return peelf::ForgivingValue<std::vector<peelf::ThreadInfo>>{
            .value = threads_,
            .status = threads_status_,
        };
    }

    void BinaryModel::select_thread(peelf::ThreadId tid) {
        selected_tid_ = tid;
        refresh_selected_thread_inspection();
    }

    void BinaryModel::refresh_selected_thread_inspection() {
        if (!is_live_process() || !selected_tid_) {
            selected_thread_context_ = {};
            selected_thread_stack_ = {};
            selected_thread_locals_ = {};
            thread_env_ = {};
            return;
        }

        const peelf::ThreadId tid = *selected_tid_;
        peelf::ThreadContext ctx = session_->thread_context(tid);
        selected_thread_context_ = peelf::ForgivingValue<peelf::ThreadContext>{
            .value = ctx,
            .status = ctx.status,
        };

        const peelf::ThreadInfo* matched_tinfo = nullptr;
        for (const peelf::ThreadInfo& th : threads_) {
            if (th.tid == tid) {
                matched_tinfo = &th;
                break;
            }
        }

        const peelf::AddressSymbolResolver sym_fn = [this](std::uint64_t va) -> std::string {
            return resolve_address_symbol(va);
        };

        if (ctx.status.has_data()) {
            selected_thread_stack_ = peelf::unwind_and_inspect_stack(
                *session_,
                ctx,
                regions_,
                modules_,
                image_.get(),
                sym_fn);
        } else {
            selected_thread_stack_ = {};
            selected_thread_stack_.status = ctx.status;
        }

        const std::string_view mod_name = active_module() != nullptr
            ? std::string_view(active_module()->name)
            : std::string_view{};
        selected_thread_locals_ = peelf::inspect_thread_locals(
            image_.get(),
            analysis_image_bytes(),
            session_.get(),
            ctx.status.has_data() ? &ctx : nullptr,
            regions_,
            mod_name);

        if (matched_tinfo != nullptr) {
            thread_env_ = peelf::inspect_thread_environment(
                *session_,
                *matched_tinfo,
                ctx.status.has_data() ? &ctx : nullptr,
                regions_);
        } else {
            thread_env_ = {};
        }
    }

    peelf::Result<peelf::MemorySearchReport> BinaryModel::search_memory(
        const peelf::MemorySearchQuery& query) const {
        if (is_live_process()) {
            const std::optional<peelf::MemoryRegion> sel_reg =
                active_region() != nullptr ? std::optional<peelf::MemoryRegion>(*active_region()) : std::nullopt;
            const std::optional<peelf::ModuleInfo> act_mod =
                active_module() != nullptr ? std::optional<peelf::ModuleInfo>(*active_module()) : std::nullopt;
            return peelf::search_process_memory(
                *session_,
                regions_,
                query,
                sel_reg,
                act_mod);
        }

        if (!has_file() || view_size() == 0) {
            return peelf::make_error("No file or live process loaded for search");
        }

        auto effective = read_effective_bytes(0, view_size());
        if (!effective) {
            return std::unexpected(effective.error());
        }

        const std::string label = file_info_.path.empty()
            ? std::string("File")
            : std::filesystem::path(file_info_.path).filename().string();
        auto res = peelf::search_buffer(
            *effective,
            0u,
            query,
            label,
            peelf::MemoryRegionKind::Image);
        if (!res) {
            return std::unexpected(res.error());
        }

        peelf::MemorySearchReport report = std::move(*res);
        for (peelf::MemorySearchHit& hit : report.hits) {
            const std::uint64_t file_off = hit.address;
            hit.view_offset = file_off;
            if (image_ != nullptr) {
                if (const auto va = image_->file_offset_to_virtual_address(file_off)) {
                    hit.address = *va;
                }
                for (const peelf::Section& sec : image_->sections()) {
                    if (file_off >= sec.file_offset && file_off < sec.file_offset + sec.file_size) {
                        hit.region_label = sec.name;
                        break;
                    }
                }
            }
        }
        return report;
    }

    void BinaryModel::refresh_runtime_and_handlers() {
        if (image_ != nullptr) {
            header_flags_ = peelf::harvest_header_flags(*image_);
        } else {
            header_flags_ = {};
            header_flags_.status = peelf::SubsystemStatus::unavailable(
                "headers",
                "No parsed PE/ELF headers for the active selection");
        }

        const auto sym_fn = [this](std::uint64_t va) -> std::string {
            return resolve_address_symbol(va);
        };

        if (is_live_process()) {
            process_env_ = peelf::inspect_process_environment(
                *session_,
                regions_,
                modules_,
                image_.get());

            const peelf::ThreadInfo* matched_tinfo = nullptr;
            if (selected_tid_) {
                for (const peelf::ThreadInfo& th : threads_) {
                    if (th.tid == *selected_tid_) {
                        matched_tinfo = &th;
                        break;
                    }
                }
            }
            if (matched_tinfo != nullptr) {
                const peelf::ThreadContext* ctx_ptr =
                    (selected_thread_context_.has_value() && selected_thread_context_.status.has_data())
                        ? &(*selected_thread_context_.value)
                        : nullptr;
                thread_env_ = peelf::inspect_thread_environment(
                    *session_,
                    *matched_tinfo,
                    ctx_ptr,
                    regions_);
            } else {
                thread_env_ = {};
            }
        } else {
            process_env_ = {};
            process_env_.core_status = peelf::SubsystemStatus::unavailable(
                "static",
                "Static file mode (attach to a running process to inspect live PEB / auxv / link_map)");
            thread_env_ = {};
            thread_env_.status = peelf::SubsystemStatus::unavailable(
                "static",
                "Static file mode (attach to a running process to inspect live TEB / TCB)");
        }

        const peelf::ThreadContext* ctx_ptr =
            (is_live_process() && selected_thread_context_.has_value() && selected_thread_context_.status.has_data())
                ? &(*selected_thread_context_.value)
                : nullptr;
        handlers_report_ = peelf::inspect_handlers(
            image_.get(),
            analysis_image_bytes(),
            is_live_process() ? session_.get() : nullptr,
            regions_,
            modules_,
            ctx_ptr,
            sym_fn);

        const peelf::ProcessSecurityProfile* cached_sec =
            (process_internals_loaded_ && process_internals_.security.has_value())
                ? &(*process_internals_.security.value)
                : nullptr;
        if (image_ != nullptr) {
            security_audit_ = peelf::audit_security(
                *image_,
                analysis_image_bytes(),
                is_live_process() ? session_.get() : nullptr,
                cached_sec);
        } else if (is_live_process() && session_ != nullptr) {
            security_audit_ = peelf::audit_live_process_security(*session_, cached_sec);
        } else {
            security_audit_ = {};
            security_audit_.status = peelf::SubsystemStatus::unavailable(
                "security_audit",
                "Open a PE/ELF image or attach to a process to evaluate security rules");
        }
    }

    void BinaryModel::refresh_process_internals() {
        if (!is_live_process() || session_ == nullptr) {
            process_internals_ = {};
            process_internals_.handles.status = peelf::SubsystemStatus::unavailable(
                "process", "Not attached to a live process");
            process_internals_.sockets.status = peelf::SubsystemStatus::unavailable(
                "process", "Not attached to a live process");
            process_internals_.security.status = peelf::SubsystemStatus::unavailable(
                "process", "Not attached to a live process");
            process_internals_loaded_ = false;
            return;
        }
        process_internals_ = peelf::inspect_process_internals(*session_);
        process_internals_loaded_ = true;
        const peelf::ProcessSecurityProfile* cached_sec =
            process_internals_.security.has_value() ? &(*process_internals_.security.value) : nullptr;
        if (image_ != nullptr) {
            security_audit_ = peelf::audit_security(*image_, analysis_image_bytes(), session_.get(), cached_sec);
        } else {
            security_audit_ = peelf::audit_live_process_security(*session_, cached_sec);
        }
    }

} // namespace viewer
