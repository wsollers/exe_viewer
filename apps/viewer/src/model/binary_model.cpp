#include "binary_model.hpp"
#include "pe_model.hpp"
#include "pe_parser.hpp"
#include "symbols/debug_symbols.hpp"

#include <peelf/error.hpp>

#include <algorithm>
#include <array>
#include <cstdio>
#include <fstream>
#include <limits>
#include <utility>

namespace viewer {
namespace {

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
        source_kind_ = BinarySourceKind::None;
        live_target_kind_ = LiveViewTargetKind::None;
        format_ = BinaryFormat::None;
        architecture_ = peelf::Architecture::Unknown;
        endianness_ = peelf::Endianness::Little;
        file_info_ = {};
        bytes_.clear();
        live_pe_backing_bytes_.clear();
        sections_.clear();
        pe_.reset();
        image_.reset();
        editable_image_.reset();
        symbol_index_ = {};
        debug_symbols_by_key_.clear();
        session_.reset();
        regions_.clear();
        modules_.clear();
        active_module_index_.reset();
        active_region_index_.reset();
        live_window_base_ = 0;
        live_window_size_ = 0;
        live_patches_.clear();
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

    void BinaryModel::rebuild_symbol_index() {
        if (!image_) {
            symbol_index_ = {};
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
        }
    }

    bool BinaryModel::load_file(const std::string& path) {
        std::ifstream f(path, std::ios::binary);
        if (!f) {
            last_diagnostic_ = "Failed to open file: " + path;
            return false;
        }

        std::vector<std::uint8_t> loaded_bytes(
            (std::istreambuf_iterator<char>(f)),
            std::istreambuf_iterator<char>()
        );

        reset_all();
        bytes_ = std::move(loaded_bytes);

        if (bytes_.size() < 2) {
            bytes_.clear();
            last_diagnostic_ = "File is too small to be a PE or ELF image";
            return false;
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
                source_kind_ = BinarySourceKind::StaticFile;
                if (architecture_ == peelf::Architecture::Unknown && pe_) {
                    architecture_ = pe_->is_pe32_plus ? peelf::Architecture::X86_64
                                                      : peelf::Architecture::X86;
                }
                if (auto editable = peelf::PagedBinaryImage::open(path)) {
                    editable_image_ = std::move(*editable);
                }
                rebuild_symbol_index();
            }
            return loaded;
        }

        // ELF -> identity from the unified image.
        if (image_ && image_->format() == peelf::Format::ELF) {
            const bool loaded = load_elf(path);
            if (loaded) {
                source_kind_ = BinarySourceKind::StaticFile;
                if (auto editable = peelf::PagedBinaryImage::open(path)) {
                    editable_image_ = std::move(*editable);
                }
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
        endianness_ = peelf::Endianness::Little;

        return refresh_process_map();
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
        pe_.reset();
        image_.reset();
        sections_.clear();

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
            file_info_.format_str = std::string(peelf::to_string(image_->format())) + " (Live RAM)";
            file_info_.arch_str = std::string(peelf::to_string(image_->architecture()));
            file_info_.size_bytes = live_window_size_;
            file_info_.entry_point = image_->entry_point();
            file_info_.flags.clear();
            file_info_.flags.push_back("Live PID " + std::to_string(session_->pid()));
            file_info_.flags.push_back("Base " + format_hex_addr(mod.base_address));
            file_info_.flags.push_back(std::string(peelf::to_string(image_->kind())));
            file_info_.flags.push_back(image_->is_64bit() ? "64-bit" : "32-bit");

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

            rebuild_symbol_index();
            if (!mod.path.empty() &&
                debug_symbols_by_key_.find(current_debug_symbol_key()) == debug_symbols_by_key_.end()) {
                if (const auto pdb = find_local_codeview_pdb(*image_, mod.path)) {
                    const DebugSymbolLoadResult pdb_res = load_pdb_debug_symbols(*pdb, *image_);
                    if (pdb_res.status == DebugSymbolLoadStatus::Loaded && !pdb_res.symbols.empty()) {
                        add_debug_symbols(pdb_res.symbols);
                    }
                }
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
        endianness_ = peelf::Endianness::Little;
        live_window_base_ = mod.base_address;
        live_window_size_ = std::max<std::uint64_t>(mod.size, 4096u);
        symbol_index_ = {};

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
        live_window_base_ = reg.start_address;
        live_window_size_ = reg.size();

        pe_.reset();
        image_.reset();
        sections_.clear();
        symbol_index_ = {};
        format_ = BinaryFormat::None;
        architecture_ = session_->info().architecture != peelf::Architecture::Unknown
                            ? session_->info().architecture
                            : peelf::Architecture::X86_64;
        endianness_ = peelf::Endianness::Little;

        // If this standalone region starts with an in-RAM PE or ELF header (e.g. [vdso]
        // or manually mapped module), parse it opportunistically.
        if (reg.protection.readable && reg.size() >= 64) {
            const auto probe_sz = static_cast<std::size_t>(
                std::min<std::uint64_t>(reg.size(), 4ull * 1024ull * 1024ull));
            const peelf::MemorySample sample =
                peelf::read_memory_tolerant(*session_, regions_, reg.start_address, probe_sz);
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

        const std::string region_name = !reg.pathname.empty()
            ? reg.pathname
            : ("[" + std::string(peelf::to_string(reg.kind)) + "]");
        file_info_.path = region_name;
        file_info_.format_str = image_
            ? (std::string(peelf::to_string(image_->format())) + " Region (Live RAM)")
            : "Memory Region (Live RAM)";
        file_info_.arch_str = std::string(peelf::to_string(architecture_));
        file_info_.size_bytes = reg.size();
        file_info_.entry_point = image_ ? image_->entry_point() : reg.start_address;
        file_info_.flags = {
            "Live PID " + std::to_string(session_->pid()),
            "Range " + format_hex_addr(reg.start_address) + " - " + format_hex_addr(reg.end_address),
            "Perms " + peelf::format_protection(reg.protection),
            "Kind " + std::string(peelf::to_string(reg.kind)),
        };

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
        symbol_index_.add_debug_symbols(*image_, rebased);
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

        file_info_.path = path;
        file_info_.format_str = "PE";
        file_info_.arch_str = result.is_64 ? "x64" : "x86";
        file_info_.size_bytes = bytes_.size();
        file_info_.entry_point = result.entry_point_va;
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
            peelf::MemorySample sample = peelf::read_memory_tolerant(
                *session_, regions_, va, static_cast<std::size_t>(size));
            live_patches_.apply_overlay(va, sample);
            return sample;
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
            return peelf::make_error("no editable binary image is loaded");
        }
        return editable_image_->read_effective(offset, size);
    }

    peelf::Result<void> BinaryModel::apply_patch_bytes(std::uint64_t offset,
                                                       std::span<const std::uint8_t> bytes,
                                                       std::string label) {
        if (is_live_process()) {
            if (offset > live_window_size_ || bytes.size() > live_window_size_ - offset) {
                return peelf::make_error("patch range exceeds active live window");
            }
            return stage_patch_at_va(live_window_base_ + offset, bytes, std::move(label));
        }

        if (!editable_image_) {
            return peelf::make_error("no editable binary image is loaded");
        }
        return editable_image_->apply_patch(offset, bytes, std::move(label));
    }

    peelf::Result<void> BinaryModel::stage_patch_at_va(std::uint64_t virtual_address,
                                                       std::span<const std::uint8_t> bytes,
                                                       std::string label) {
        if (!is_live_process()) {
            return peelf::make_error("live VA patching requires an attached process");
        }
        auto res = live_patches_.stage_patch(*session_, virtual_address, bytes, std::move(label));
        if (!res) {
            last_diagnostic_ = res.error().message;
        }
        return res;
    }

    peelf::Result<void> BinaryModel::undo_patch() {
        if (is_live_process()) {
            return live_patches_.undo(*session_);
        }
        if (!editable_image_) {
            return peelf::make_error("no editable binary image is loaded");
        }
        return editable_image_->undo();
    }

    peelf::Result<void> BinaryModel::redo_patch() {
        if (is_live_process()) {
            return live_patches_.redo(*session_);
        }
        if (!editable_image_) {
            return peelf::make_error("no editable binary image is loaded");
        }
        return editable_image_->redo();
    }

    void BinaryModel::discard_staged_patches() noexcept {
        if (is_live_process()) {
            live_patches_.clear_staged();
        }
    }

    peelf::Result<std::size_t> BinaryModel::commit_patches_to_process(
        peelf::MemoryWriteOptions options) {
        if (!is_live_process()) {
            return peelf::make_error("cannot commit to RAM without an attached process");
        }
        if (!session_->is_alive()) {
            last_diagnostic_ = "Attached process PID " + std::to_string(session_->pid()) + " has exited";
            return peelf::make_error(last_diagnostic_);
        }
        auto committed = live_patches_.commit_to_process(*session_, options);
        if (!committed) {
            last_diagnostic_ = committed.error().message;
        }
        return committed;
    }

    peelf::Result<std::size_t> BinaryModel::revert_committed_patches(
        peelf::MemoryWriteOptions options) {
        if (!is_live_process()) {
            return peelf::make_error("cannot revert RAM patches without an attached process");
        }
        if (!session_->is_alive()) {
            last_diagnostic_ = "Attached process PID " + std::to_string(session_->pid()) + " has exited";
            return peelf::make_error(last_diagnostic_);
        }
        auto reverted = live_patches_.revert_committed(*session_, options);
        if (!reverted) {
            last_diagnostic_ = reverted.error().message;
        }
        return reverted;
    }

    peelf::Result<void> BinaryModel::revert_committed_patch_at(
        std::uint64_t virtual_address,
        std::uint64_t size,
        peelf::MemoryWriteOptions options) {
        if (!is_live_process()) {
            return peelf::make_error("cannot revert RAM patch without an attached process");
        }
        if (!session_->is_alive()) {
            last_diagnostic_ = "Attached process PID " + std::to_string(session_->pid()) + " has exited";
            return peelf::make_error(last_diagnostic_);
        }
        auto reverted = live_patches_.revert_committed_interval(*session_, virtual_address, size, options);
        if (!reverted) {
            last_diagnostic_ = reverted.error().message;
        }
        return reverted;
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

} // namespace viewer
