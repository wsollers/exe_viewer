#include "binary_model.hpp"
#include "binary_model_internal.hpp"
#include "symbols/debug_symbols.hpp"

#include <peelf/dwarf.hpp>
#include <peelf/error.hpp>

#include <algorithm>
#include <format>
#include <fstream>
#include <limits>
#include <utility>

namespace viewer {
namespace {
using detail::format_hex_addr;
using detail::utf8_path;

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

class DebugSessionProcessProxy final : public peelf::IProcessSession {
public:
    explicit DebugSessionProcessProxy(std::shared_ptr<peelf::debugger::IDebugSession> dbg) noexcept
        : dbg_(std::move(dbg)) {}

    [[nodiscard]] const peelf::ProcessInfo& info() const noexcept override {
        return dbg_->session().info();
    }
    [[nodiscard]] bool is_alive() const noexcept override {
        return dbg_->session().is_alive();
    }
    [[nodiscard]] bool is_read_only() const noexcept override {
        return dbg_->session().is_read_only();
    }
    [[nodiscard]] bool is_crash_dump() const noexcept override {
        return dbg_->session().is_crash_dump();
    }
    [[nodiscard]] bool is_suspended() const noexcept override {
        return dbg_->state() == peelf::debugger::DebugSessionState::Paused ||
               dbg_->session().is_suspended();
    }
    [[nodiscard]] peelf::Result<void> suspend() override {
        return dbg_->pause_execution();
    }
    [[nodiscard]] peelf::Result<void> resume() override {
        return dbg_->continue_execution(false);
    }
    [[nodiscard]] peelf::Result<void> suspend_thread(peelf::ThreadId tid) override {
        return dbg_->session().suspend_thread(tid);
    }
    [[nodiscard]] peelf::Result<void> resume_thread(peelf::ThreadId tid) override {
        return dbg_->session().resume_thread(tid);
    }
    [[nodiscard]] peelf::Result<std::vector<peelf::MemoryRegion>> memory_regions() override {
        return dbg_->session().memory_regions();
    }
    [[nodiscard]] peelf::ForgivingValue<peelf::ProcessMemorySummary> memory_summary(
        std::span<const peelf::MemoryRegion> regions) override {
        return dbg_->session().memory_summary(regions);
    }
    [[nodiscard]] peelf::Result<std::vector<peelf::ModuleInfo>> modules() override {
        return dbg_->session().modules();
    }
    [[nodiscard]] peelf::Result<std::vector<peelf::ThreadInfo>> threads() override {
        return dbg_->session().threads();
    }
    [[nodiscard]] peelf::ThreadContext thread_context(peelf::ThreadId tid) override {
        return dbg_->session().thread_context(tid);
    }
    [[nodiscard]] peelf::ForgivingValue<std::vector<std::uint8_t>> proc_auxv() override {
        return dbg_->session().proc_auxv();
    }
    [[nodiscard]] peelf::ForgivingValue<std::string> proc_status_text() override {
        return dbg_->session().proc_status_text();
    }
    [[nodiscard]] peelf::ForgivingValue<std::vector<std::string>> environment_variables() override {
        return dbg_->session().environment_variables();
    }
    [[nodiscard]] peelf::ForgivingValue<std::uint64_t> process_environment_block_address() override {
        return dbg_->session().process_environment_block_address();
    }
    [[nodiscard]] peelf::Result<std::size_t> read_memory(
        std::uint64_t address,
        std::span<std::uint8_t> buffer) override {
        return dbg_->session().read_memory(address, buffer);
    }
    [[nodiscard]] peelf::Result<std::size_t> write_memory(
        std::uint64_t address,
        std::span<const std::uint8_t> data,
        peelf::MemoryWriteOptions options) override {
        return dbg_->session().write_memory(address, data, options);
    }

private:
    std::shared_ptr<peelf::debugger::IDebugSession> dbg_;
};

} // namespace

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

    void BinaryModel::set_debug_backend(std::shared_ptr<peelf::debugger::IDebugBackend> backend) {
        debug_backend_ = std::move(backend);
    }

    peelf::debugger::IDebugBackend& BinaryModel::debug_backend() {
        if (!debug_backend_) {
            debug_backend_ = peelf::debugger::create_native_debug_backend();
        }
        return *debug_backend_;
    }

    peelf::Result<void> BinaryModel::launch_debug_process(
        const std::filesystem::path& executable,
        std::span<const std::string> args,
        const std::filesystem::path& working_dir) {
        auto launched = debug_backend().launch(executable, args, working_dir);
        if (!launched) {
            last_diagnostic_ = launched.error().message;
            return std::unexpected(launched.error());
        }
        return attach_debug_session(std::move(*launched));
    }

    peelf::Result<void> BinaryModel::attach_debug_process(peelf::ProcessId pid) {
        auto attached = debug_backend().attach(pid);
        if (!attached) {
            last_diagnostic_ = attached.error().message;
            return std::unexpected(attached.error());
        }
        return attach_debug_session(std::move(*attached));
    }

    peelf::Result<void> BinaryModel::attach_debug_session(
        std::unique_ptr<peelf::debugger::IDebugSession> debug_session) {
        if (!debug_session) {
            last_diagnostic_ = "Debug session is null";
            return peelf::make_error(last_diagnostic_);
        }

        reset_all();
        debug_session_ = std::shared_ptr<peelf::debugger::IDebugSession>(std::move(debug_session));
        session_ = std::make_shared<DebugSessionProcessProxy>(debug_session_);
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
        refresh_debug_breakpoints();
        (void)sync_debugger_stop_state();
        return map_res;
    }

    std::optional<std::uint64_t> BinaryModel::sync_debugger_stop_state() {
        if (!debug_session_) {
            return std::nullopt;
        }

        const peelf::debugger::DebugStopStatus st = debug_session_->stop_status();
        if (st.stop_revision == last_synced_debug_stop_revision_) {
            return std::nullopt;
        }
        last_synced_debug_stop_revision_ = st.stop_revision;
        refresh_debug_breakpoints();

        if (st.state != peelf::debugger::DebugSessionState::Paused) {
            return std::nullopt;
        }

        if (!current_debug_registers_.empty()) {
            previous_debug_registers_ = current_debug_registers_;
            has_previous_debug_stop_ = true;
        }

        (void)refresh_process_map();
        (void)refresh_threads();
        if (st.active_tid != 0u) {
            select_thread(st.active_tid);
        } else {
            refresh_selected_thread_inspection();
        }
        refresh_runtime_and_handlers();

        current_debug_registers_.clear();
        if (selected_thread_context_.has_value()) {
            for (const peelf::RegisterValue& rv : selected_thread_context_.value->registers) {
                current_debug_registers_[rv.name] = rv.value_u64;
            }
        }

        if (st.instruction_pointer != 0u) {
            (void)navigate_to_virtual_address(st.instruction_pointer);
            return st.instruction_pointer;
        }
        return std::nullopt;
    }

    void BinaryModel::refresh_debug_breakpoints() {
        if (debug_session_) {
            debug_breakpoints_ = debug_session_->breakpoints();
        } else {
            debug_breakpoints_.clear();
        }
    }

    const peelf::debugger::BreakpointDescriptor* BinaryModel::find_breakpoint_at(
        std::uint64_t virtual_address) const noexcept {
        for (const peelf::debugger::BreakpointDescriptor& bp : debug_breakpoints_) {
            if (bp.address == virtual_address) {
                return &bp;
            }
        }
        return nullptr;
    }

    peelf::Result<bool> BinaryModel::toggle_software_breakpoint(
        std::uint64_t virtual_address,
        std::string label) {
        if (!debug_session_) {
            last_diagnostic_ = "No active opt-in debugger session";
            return peelf::make_error(last_diagnostic_);
        }
        refresh_debug_breakpoints();
        if (const auto* existing = find_breakpoint_at(virtual_address); existing != nullptr) {
            const auto id = existing->id;
            auto rem = debug_session_->remove_breakpoint(id);
            refresh_debug_breakpoints();
            if (!rem) {
                last_diagnostic_ = rem.error().message;
                return std::unexpected(rem.error());
            }
            return false;
        }
        if (label.empty()) {
            label = resolve_address_symbol(virtual_address);
        }
        auto added = debug_session_->add_software_breakpoint(
            virtual_address,
            std::move(label),
            analysis_thumb_mode_);
        refresh_debug_breakpoints();
        if (!added) {
            last_diagnostic_ = added.error().message;
            return std::unexpected(added.error());
        }
        return true;
    }

    bool BinaryModel::has_debug_register_changed(
        std::string_view reg_name,
        std::uint64_t current_value) const noexcept {
        if (!has_previous_debug_stop_) {
            return false;
        }
        const auto it = previous_debug_registers_.find(reg_name);
        return it != previous_debug_registers_.end() && it->second != current_value;
    }

    std::optional<std::uint64_t> BinaryModel::previous_debug_register_value(
        std::string_view reg_name) const noexcept {
        if (!has_previous_debug_stop_) {
            return std::nullopt;
        }
        const auto it = previous_debug_registers_.find(reg_name);
        if (it == previous_debug_registers_.end()) {
            return std::nullopt;
        }
        return it->second;
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
