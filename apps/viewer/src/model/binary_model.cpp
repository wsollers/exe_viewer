#include "binary_model.hpp"
#include "binary_model_internal.hpp"
#include "symbols/debug_symbols.hpp"

#include <peelf/dwarf.hpp>
#include <peelf/error.hpp>
#include <peelf/sha256.hpp>

#include <algorithm>
#include <array>
#include <bit>
#include <format>
#include <fstream>
#include <limits>
#include <utility>

namespace viewer {
namespace {
using detail::format_hex_addr;
using detail::utf8_path;

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

    BinaryModel::BinaryModel() {
        reset_timeline_sources();
    }

    void BinaryModel::reset_timeline_sources() {
        debug_timeline_source_.reset();
        execution_timeline_.clear(true);
        execution_timeline_.clear_sources();
        execution_timeline_.register_source(peelf::create_syscall_timeline_source());
        execution_timeline_.register_source(peelf::create_etw_timeline_source());
    }

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
        sections_.clear();
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
        if (debug_session_ != nullptr) {
            (void)debug_session_->detach();
            debug_session_.reset();
        }
        debug_breakpoints_.clear();
        last_synced_debug_stop_revision_ = 0;
        previous_debug_registers_.clear();
        current_debug_registers_.clear();
        has_previous_debug_stop_ = false;
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
        executable_settings_ = {};
        environment_redaction_policy_ = peelf::EnvironmentRedactionPolicy::RedactSensitiveDefault;
        launched_debug_session_ = false;
        captured_snapshots_.clear();
        latest_snapshot_diff_.reset();
        timeline_proven_dynamic_bases_.clear();
        reset_timeline_sources();
        process_internals_ = {};
        process_internals_loaded_ = false;
        thread_cpu_tracker_.reset();
        target_profile_ = {};
        capability_matrix_ = peelf::capabilities_for(target_profile_, provider_facts_);
        target_instance_id_ = {};
        backing_identity_status_ = {};
        next_capture_revision_ = 0;
        in_coordinated_attach_ = false;
        static_image_stamp_ = {};
        memory_map_stamp_ = {};
        threads_stamp_ = {};
        selected_thread_stamp_ = {};
        runtime_stamp_ = {};
        process_internals_stamp_ = {};
        last_diagnostic_.clear();
    }

    void BinaryModel::recompute_capabilities() noexcept {
        try {
            const peelf::IProcessSession* underlying_session =
                is_live_process()
                    ? (debug_session_ != nullptr ? &debug_session_->session() : session_.get())
                    : nullptr;
            const bool dbg_active =
                debug_session_ != nullptr ||
                (underlying_session != nullptr &&
                 !underlying_session->is_read_only() &&
                 !underlying_session->is_crash_dump());
            const auto* gdb_ro = dynamic_cast<const peelf::IGdbRemoteSession*>(underlying_session);
            const auto* gdb_dbg =
                dynamic_cast<const peelf::IGdbRemoteDebugSession*>(debug_session_.get());
            target_profile_ = peelf::derive_target_profile(
                image_.get(),
                underlying_session,
                dbg_active,
                gdb_ro != nullptr || gdb_dbg != nullptr);
            if (!is_live_process() && source_kind_ == BinarySourceKind::None) {
                target_profile_ = {};
            }
            peelf::ProviderFacts effective_facts = provider_facts_;
            if (gdb_ro != nullptr || gdb_dbg != nullptr) {
                effective_facts.remote_gdb_stub_available = true;
            }
            capability_matrix_ = peelf::capabilities_for(target_profile_, effective_facts);
            if (gdb_dbg != nullptr) {
                const peelf::TargetCapabilityMatrix sess_mat = gdb_dbg->capability_matrix();
                std::array<peelf::Capability, peelf::kOperationCount> merged{};
                const auto base_entries = capability_matrix_.entries();
                std::copy(base_entries.begin(), base_entries.end(), merged.begin());
                for (const peelf::Operation op : {
                         peelf::Operation::SoftwareBreakpoints,
                         peelf::Operation::HardwareWatchpoints,
                         peelf::Operation::ExecutionTimeline}) {
                    merged[static_cast<std::size_t>(op)] = sess_mat.get(op);
                }
                effective_facts.remote_gdb_stub_available =
                    sess_mat.provider_facts().remote_gdb_stub_available;
                capability_matrix_ = peelf::TargetCapabilityMatrix(
                    target_profile_, effective_facts, std::move(merged));
            } else if (gdb_ro != nullptr && !dbg_active) {
                std::array<peelf::Capability, peelf::kOperationCount> merged{};
                const auto base_entries = capability_matrix_.entries();
                std::copy(base_entries.begin(), base_entries.end(), merged.begin());
                merged[static_cast<std::size_t>(peelf::Operation::SoftwareBreakpoints)] =
                    peelf::Capability{
                        .operation = peelf::Operation::SoftwareBreakpoints,
                        .state = peelf::SupportState::Unsupported,
                        .provider_available = effective_facts.remote_gdb_stub_available,
                        .provider_name = "gdb_rsp",
                        .reason = "Read-only GDB RSP session; connect via Opt-In GDB Remote Debugger for software breakpoints",
                    };
                merged[static_cast<std::size_t>(peelf::Operation::HardwareWatchpoints)] =
                    peelf::Capability{
                        .operation = peelf::Operation::HardwareWatchpoints,
                        .state = peelf::SupportState::Unsupported,
                        .provider_available = effective_facts.remote_gdb_stub_available,
                        .provider_name = "gdb_rsp",
                        .reason = "Read-only GDB RSP session; connect via Opt-In GDB Remote Debugger for watchpoints",
                    };
                capability_matrix_ = peelf::TargetCapabilityMatrix(
                    target_profile_, effective_facts, std::move(merged));
            }
        } catch (...) {
        }
    }

    void BinaryModel::set_provider_facts(peelf::ProviderFacts facts) noexcept {
        provider_facts_ = facts;
        recompute_capabilities();
    }

    void BinaryModel::mark_live_volatile_stamps_stale(bool include_paused_stamps) noexcept {
        auto degrade = [include_paused_stamps](peelf::CaptureStamp& stamp) noexcept {
            if (stamp.availability == peelf::CaptureAvailability::Complete ||
                stamp.availability == peelf::CaptureAvailability::Partial) {
                if (include_paused_stamps || !stamp.target_paused) {
                    stamp.availability = peelf::CaptureAvailability::Stale;
                }
            }
        };
        degrade(memory_map_stamp_);
        degrade(threads_stamp_);
        degrade(selected_thread_stamp_);
        degrade(runtime_stamp_);
        degrade(process_internals_stamp_);
    }

    peelf::CaptureStamp BinaryModel::advance_live_capture_stamp(
        peelf::CaptureAvailability availability) noexcept {
        const bool paused = is_process_suspended() || is_crash_dump();
        if (!in_coordinated_attach_ && !paused) {
            mark_live_volatile_stamps_stale(false);
        }
        return peelf::CaptureStamp::capture_now(
            target_instance_id_,
            ++next_capture_revision_,
            paused,
            availability);
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
            rec.heuristic_discovered = true;
            symbol_index_.add_discovered_symbol(std::move(rec));
        }

        refresh_runtime_and_handlers();
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

        // PE (MZ) -> unified PeImage.
        if (bytes_[0] == 'M' && bytes_[1] == 'Z') {
            const bool loaded = load_pe(path);
            if (loaded) {
                ++content_generation_;
                source_kind_ = BinarySourceKind::StaticFile;
                if (auto editable = peelf::PagedBinaryImage::open(utf8_path(path))) {
                    editable_image_ = std::move(*editable);
                }
                const peelf::BackingImageIdentity bid = peelf::extract_backing_image_identity(
                    *image_, bytes_);
                target_instance_id_ = peelf::TargetInstanceId{
                    .backend = peelf::BackendKind::StaticFile,
                    .pid = 0u,
                    .creation_identity = std::nullopt,
                    .image_sha256 = content_sha256(),
                    .build_id_or_pdb_guid = bid.primary_identifier(),
                };
                static_image_stamp_ = peelf::CaptureStamp::capture_now(
                    target_instance_id_,
                    ++next_capture_revision_,
                    true,
                    peelf::CaptureAvailability::Complete);
                memory_map_stamp_ = peelf::CaptureStamp::unavailable_for(target_instance_id_);
                threads_stamp_ = peelf::CaptureStamp::unavailable_for(target_instance_id_);
                selected_thread_stamp_ = peelf::CaptureStamp::unavailable_for(target_instance_id_);
                process_internals_stamp_ = peelf::CaptureStamp::unavailable_for(target_instance_id_);
                (void)auto_load_debug_info_for_current_image(utf8_path(path));
                rebuild_symbol_index();
                runtime_stamp_ = peelf::CaptureStamp::capture_now(
                    target_instance_id_,
                    ++next_capture_revision_,
                    true,
                    peelf::CaptureAvailability::Partial);
                recompute_capabilities();
            }
            return loaded;
        }

        // ELF / Mach-O -> identity from the unified image.
        if (image_ && (image_->format() == peelf::Format::ELF ||
                       image_->format() == peelf::Format::MachO)) {
            const bool loaded = image_->format() == peelf::Format::ELF
                ? load_elf(path)
                : load_macho(path);
            if (loaded) {
                ++content_generation_;
                source_kind_ = BinarySourceKind::StaticFile;
                if (auto editable = peelf::PagedBinaryImage::open(utf8_path(path))) {
                    editable_image_ = std::move(*editable);
                }
                const peelf::BackingImageIdentity bid = peelf::extract_backing_image_identity(
                    *image_, bytes_);
                target_instance_id_ = peelf::TargetInstanceId{
                    .backend = peelf::BackendKind::StaticFile,
                    .pid = 0u,
                    .creation_identity = std::nullopt,
                    .image_sha256 = content_sha256(),
                    .build_id_or_pdb_guid = bid.primary_identifier(),
                };
                static_image_stamp_ = peelf::CaptureStamp::capture_now(
                    target_instance_id_,
                    ++next_capture_revision_,
                    true,
                    peelf::CaptureAvailability::Complete);
                memory_map_stamp_ = peelf::CaptureStamp::unavailable_for(target_instance_id_);
                threads_stamp_ = peelf::CaptureStamp::unavailable_for(target_instance_id_);
                selected_thread_stamp_ = peelf::CaptureStamp::unavailable_for(target_instance_id_);
                process_internals_stamp_ = peelf::CaptureStamp::unavailable_for(target_instance_id_);
                (void)auto_load_debug_info_for_current_image(utf8_path(path));
                rebuild_symbol_index();
                runtime_stamp_ = peelf::CaptureStamp::capture_now(
                    target_instance_id_,
                    ++next_capture_revision_,
                    true,
                    peelf::CaptureAvailability::Partial);
                recompute_capabilities();
            }
            return loaded;
        }

        reset_all();
        last_diagnostic_ = "Unsupported executable format: " + path;
        return false;
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

    peelf::Observed<ResolvedSymbolInfo> BinaryModel::resolve_symbol_with_provenance(
        std::uint64_t virtual_address) const {
        const peelf::CaptureStamp& base_stamp =
            is_live_process() ? memory_map_stamp_ : static_image_stamp_;
        const peelf::ProvenanceTag base_tag =
            is_crash_dump() ? peelf::ProvenanceTag::CrashDump
                            : (is_live_process() ? peelf::ProvenanceTag::LiveMemory
                                                 : peelf::ProvenanceTag::DiskFile);
        if (virtual_address == 0) {
            return peelf::Observed<ResolvedSymbolInfo>::unavailable(
                base_tag,
                "Virtual address 0x0 does not correspond to a resolved symbol",
                base_stamp);
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

        const peelf::ProvenanceTag live_tag =
            is_crash_dump() ? peelf::ProvenanceTag::CrashDump : peelf::ProvenanceTag::LiveMemory;

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

                ResolvedSymbolInfo info;
                info.display_label = std::move(label);
                info.symbol_name = sname;
                info.module_name = module_prefix;
                info.source = sym->source;
                info.symbol_va = *sym->virtual_address;
                info.offset = delta;
                info.heuristic_discovered = sym->heuristic_discovered;
                info.backing_identity_verified = !backing_identity_status_.has_mismatch();

                peelf::ProvenanceTag primary_tag = peelf::ProvenanceTag::DiskFile;
                std::vector<peelf::Evidence> evidence;
                if (sym->heuristic_discovered) {
                    primary_tag = peelf::ProvenanceTag::HeuristicInference;
                    evidence.push_back(peelf::Evidence{
                        .tag = peelf::ProvenanceTag::HeuristicInference,
                        .source = "symbol_index_heuristic",
                        .detail = "Heuristically discovered function boundary (prologue/call-target scan)",
                        .virtual_address = *sym->virtual_address,
                    });
                } else if (sym->source == SymbolSource::DebugSymbol) {
                    primary_tag = peelf::ProvenanceTag::DebugSymbols;
                    evidence.push_back(peelf::Evidence{
                        .tag = peelf::ProvenanceTag::DebugSymbols,
                        .source = "dwarf_pdb_symbols",
                        .detail = "Resolved from DWARF/PDB debug symbol table",
                        .virtual_address = *sym->virtual_address,
                    });
                } else {
                    const bool from_disk = !is_live_process() || !live_backing_file_bytes_.empty();
                    primary_tag = from_disk ? peelf::ProvenanceTag::DiskFile : live_tag;
                    evidence.push_back(peelf::Evidence{
                        .tag = primary_tag,
                        .source = from_disk ? "disk_symbol_table" : "mapped_symbol_table",
                        .detail = from_disk
                                      ? "Resolved from on-disk PE/ELF symbol/export table"
                                      : "Resolved from mapped module symbol/export table",
                        .virtual_address = *sym->virtual_address,
                    });
                }

                if (is_live_process()) {
                    evidence.push_back(peelf::Evidence{
                        .tag = live_tag,
                        .source = "live_module_rebase",
                        .detail = "Rebased to live module load address",
                        .virtual_address = virtual_address,
                    });
                }

                if (backing_identity_status_.has_mismatch()) {
                    return peelf::Observed<ResolvedSymbolInfo>::partial(
                        std::move(info),
                        primary_tag,
                        backing_identity_status_.summary,
                        base_stamp,
                        std::move(evidence));
                }

                peelf::Observed<ResolvedSymbolInfo> out;
                out.value = std::move(info);
                out.provenance = primary_tag;
                out.availability = base_stamp.availability;
                out.stamp = base_stamp;
                out.evidence = std::move(evidence);
                if (base_stamp.availability == peelf::CaptureAvailability::Stale) {
                    out.note = "Underlying module map capture is stale relative to newer process activity";
                }
                return out;
            }
        }

        if (const FunctionEntry* fn = function_index_.find_containing(virtual_address);
            fn != nullptr && fn->virtual_address != 0u) {
            const std::uint64_t delta = virtual_address - fn->virtual_address;
            const std::string& sname = fn->display_name(demangle_symbols_);
            std::string label = module_prefix.empty() ? sname : (module_prefix + "!" + sname);
            if (delta != 0u) {
                label += "+" + format_hex_addr(delta);
            }

            const bool is_heuristic = (fn->origin == FunctionOrigin::CallTargetDiscovery);
            ResolvedSymbolInfo info;
            info.display_label = std::move(label);
            info.symbol_name = sname;
            info.module_name = module_prefix;
            info.source = SymbolSource::ImageSymbol;
            info.symbol_va = fn->virtual_address;
            info.offset = delta;
            info.heuristic_discovered = is_heuristic;
            info.backing_identity_verified = !backing_identity_status_.has_mismatch();

            const peelf::ProvenanceTag primary_tag = is_heuristic
                ? peelf::ProvenanceTag::HeuristicInference
                : (!is_live_process() || !live_backing_file_bytes_.empty()
                       ? peelf::ProvenanceTag::DiskFile
                       : live_tag);
            std::vector<peelf::Evidence> evidence;
            evidence.push_back(peelf::Evidence{
                .tag = primary_tag,
                .source = is_heuristic ? "function_index_call_target" : "function_index",
                .detail = std::string(to_string(fn->origin)),
                .virtual_address = fn->virtual_address,
            });
            if (is_live_process()) {
                evidence.push_back(peelf::Evidence{
                    .tag = live_tag,
                    .source = "live_module_rebase",
                    .detail = "Rebased to live module load address",
                    .virtual_address = virtual_address,
                });
            }
            if (backing_identity_status_.has_mismatch()) {
                return peelf::Observed<ResolvedSymbolInfo>::partial(
                    std::move(info),
                    primary_tag,
                    backing_identity_status_.summary,
                    base_stamp,
                    std::move(evidence));
            }
            peelf::Observed<ResolvedSymbolInfo> out;
            out.value = std::move(info);
            out.provenance = primary_tag;
            out.availability = base_stamp.availability;
            out.stamp = base_stamp;
            out.evidence = std::move(evidence);
            if (base_stamp.availability == peelf::CaptureAvailability::Stale) {
                out.note = "Underlying module map capture is stale relative to newer process activity";
            }
            return out;
        }

        if (is_live_process()) {
            for (const peelf::ModuleInfo& mod : modules_) {
                if (virtual_address >= mod.base_address &&
                    virtual_address < mod.base_address + std::max<std::uint64_t>(mod.size, 1u)) {
                    const std::string mname = !mod.name.empty()
                        ? mod.name
                        : (!mod.path.empty() ? mod.path.filename().string() : "module");
                    const std::uint64_t rva = virtual_address - mod.base_address;
                    ResolvedSymbolInfo info;
                    info.display_label = rva == 0 ? mname : (mname + "+" + format_hex_addr(rva));
                    info.symbol_name = {};
                    info.module_name = mname;
                    info.symbol_va = mod.base_address;
                    info.offset = rva;
                    info.backing_identity_verified = !backing_identity_status_.has_mismatch();

                    const peelf::ProvenanceTag mod_tag = is_crash_dump()
                        ? peelf::ProvenanceTag::CrashDump
                        : peelf::ProvenanceTag::ProcOrOsApi;
                    return peelf::Observed<ResolvedSymbolInfo>::partial(
                        std::move(info),
                        mod_tag,
                        "No symbol table entry covers this virtual address",
                        base_stamp,
                        {peelf::Evidence{
                            .tag = mod_tag,
                            .source = "module_map",
                            .detail = "Module base offset only (no matching symbol record)",
                            .virtual_address = virtual_address,
                        }});
                }
            }
        }

        return peelf::Observed<ResolvedSymbolInfo>::unavailable(
            base_tag,
            "No symbol or mapped module covers this virtual address",
            base_stamp);
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
        if (!image_ || image_->format() != peelf::Format::PE) {
            format_ = BinaryFormat::None;
            sections_.clear();
            return false;
        }

        format_ = BinaryFormat::PE;

        file_info_.path = path;
        file_info_.format_str = "PE";
        file_info_.arch_str = std::string(peelf::to_string(image_->architecture()));
        file_info_.size_bytes = bytes_.size();
        file_info_.entry_point = image_->entry_point();

        file_info_.flags.clear();
        file_info_.flags.push_back(image_->is_64bit() ? "64-bit" : "32-bit");
        if (const peelf::PeHeader* hdr = image_->pe_header(); hdr != nullptr) {
            if ((hdr->characteristics & 0x0002u) != 0u) file_info_.flags.push_back("Executable");
            if ((hdr->characteristics & 0x2000u) != 0u) file_info_.flags.push_back("DLL");
            if ((hdr->characteristics & 0x1000u) != 0u) file_info_.flags.push_back("System");
            if ((hdr->characteristics & 0x0020u) != 0u) file_info_.flags.push_back("LargeAddressAware");
        }

        sections_.clear();
        for (const auto& s : image_->sections()) {
            sections_.push_back(SectionInfo{
                .name = s.name,
                .address = s.virtual_address,
                .size = s.virtual_size != 0u ? s.virtual_size : s.file_size,
                .flags = static_cast<std::uint32_t>(s.raw_flags)
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

    bool BinaryModel::load_macho(const std::string& path) {
        if (!image_ || image_->format() != peelf::Format::MachO) {
            return false;
        }

        format_ = BinaryFormat::MachO;

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
        const auto pid_bytes = std::bit_cast<std::array<std::uint8_t, sizeof(pid)>>(pid);
        const auto base_bytes =
            std::bit_cast<std::array<std::uint8_t, sizeof(live_window_base_)>>(live_window_base_);
        const auto size_bytes =
            std::bit_cast<std::array<std::uint8_t, sizeof(live_window_size_)>>(live_window_size_);
        hasher.update(pid_bytes);
        hasher.update(base_bytes);
        hasher.update(size_bytes);

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

} // namespace viewer
