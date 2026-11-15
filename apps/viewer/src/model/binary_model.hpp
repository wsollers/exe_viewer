#pragma once
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <limits>
#include <map>
#include <memory>
#include <optional>
#include <set>
#include <span>
#include <string>
#include <vector>

#include "analysis/function_index.hpp"
#include "pe_model.hpp"
#include "symbols/data_types.hpp"
#include "symbols/debug_symbols.hpp"
#include "symbols/symbol_index.hpp"

#include <peelf/binary_image.hpp>
#include <peelf/endian_reader.hpp>
#include <peelf/forgiving.hpp>
#include <peelf/handlers.hpp>
#include <peelf/memory_search.hpp>
#include <peelf/patching.hpp>
#include <peelf/process.hpp>
#include <peelf/process_internals.hpp>
#include <peelf/runtime_structures.hpp>
#include <peelf/stack_tls.hpp>

namespace viewer {

    enum class BinaryFormat {
        None,
        PE,
        ELF
    };

    enum class BinarySourceKind : std::uint8_t {
        None,
        StaticFile,
        LiveProcess
    };

    enum class LiveViewTargetKind : std::uint8_t {
        None,
        Module,
        Region
    };

    enum class BytePatchState : std::uint8_t {
        Unchanged,
        Staged,
        Committed
    };

    struct SectionInfo {
        std::string name;
        std::uint64_t address;
        std::uint64_t size;
        std::uint32_t flags;
    };

    struct FileInfo {
        std::string path;
        std::string format_str;
        std::string arch_str;
        std::uint64_t size_bytes = 0;
        std::uint64_t entry_point = 0;
        std::vector<std::string> flags;
    };

    class PeModel;
    class ElfModel;

    class BinaryModel {
    public:
        BinaryModel() = default;

        bool load_file(const std::string& path);

        // Live process inspection & attach API.
        void set_process_backend(std::shared_ptr<peelf::IProcessBackend> backend);
        [[nodiscard]] peelf::IProcessBackend& process_backend();
        [[nodiscard]] peelf::Result<std::vector<peelf::ProcessInfo>> list_processes();
        [[nodiscard]] peelf::Result<void> attach_process(peelf::ProcessId pid);
        [[nodiscard]] peelf::Result<void> attach_session(std::unique_ptr<peelf::IProcessSession> session);
        void detach_process();
        [[nodiscard]] peelf::Result<void> refresh_process_map();

        [[nodiscard]] peelf::Result<void> select_process_module(std::size_t module_index);
        [[nodiscard]] peelf::Result<void> select_memory_region(std::size_t region_index,
                                                               bool prefer_module_context = true);
        [[nodiscard]] std::optional<std::uint64_t> navigate_to_virtual_address(std::uint64_t virtual_address);

        [[nodiscard]] bool has_file() const { return format_ != BinaryFormat::None || is_live_process(); }
        [[nodiscard]] bool has_data_window() const noexcept { return view_size() > 0; }
        [[nodiscard]] bool is_live_process() const noexcept {
            return source_kind_ == BinarySourceKind::LiveProcess && session_ != nullptr;
        }
        [[nodiscard]] bool is_read_only() const noexcept { return is_live_process(); }
        [[nodiscard]] BinarySourceKind source_kind() const noexcept { return source_kind_; }
        [[nodiscard]] LiveViewTargetKind live_target_kind() const noexcept { return live_target_kind_; }
        [[nodiscard]] BinaryFormat format() const { return format_; }
        [[nodiscard]] peelf::Architecture architecture() const noexcept { return architecture_; }
        [[nodiscard]] peelf::Endianness endianness() const noexcept { return endianness_; }
        [[nodiscard]] peelf::TargetLayout target_layout() const noexcept;

        [[nodiscard]] const FileInfo& file_info() const { return file_info_; }
        [[nodiscard]] const std::vector<std::uint8_t>& bytes() const { return bytes_; }
        [[nodiscard]] std::span<const std::uint8_t> analysis_image_bytes() const noexcept;
        [[nodiscard]] std::uint64_t analysis_image_size() const noexcept;
        [[nodiscard]] const std::vector<SectionInfo>& sections() const { return sections_; }
        [[nodiscard]] const std::string& last_diagnostic() const noexcept { return last_diagnostic_; }

        [[nodiscard]] const PeModel* pe() const { return pe_.get(); }

        // Unified core image (format-agnostic identity). Non-null once a PE or ELF
        // file or live module parses.
        [[nodiscard]] const peelf::IBinaryImage* image() const { return image_.get(); }
        [[nodiscard]] const peelf::PagedBinaryImage* editable_image() const {
            return (!is_live_process() && editable_image_) ? &*editable_image_ : nullptr;
        }

        // Live process state accessors.
        [[nodiscard]] const peelf::IProcessSession* process_session() const noexcept { return session_.get(); }
        [[nodiscard]] peelf::IProcessSession* process_session() noexcept { return session_.get(); }
        [[nodiscard]] const std::optional<std::filesystem::path>& resolved_executable_path() const noexcept {
            return resolved_exe_path_;
        }
        [[nodiscard]] const std::vector<peelf::MemoryRegion>& memory_regions() const noexcept { return regions_; }
        [[nodiscard]] const peelf::ForgivingValue<peelf::ProcessMemorySummary>& memory_summary() const noexcept {
            return memory_summary_;
        }
        [[nodiscard]] const std::vector<peelf::AddressSpaceCluster>& address_space_clusters() const noexcept {
            return address_space_clusters_;
        }
        [[nodiscard]] const std::vector<peelf::ModuleInfo>& process_modules() const noexcept { return modules_; }
        [[nodiscard]] std::optional<std::size_t> active_module_index() const noexcept { return active_module_index_; }
        [[nodiscard]] std::optional<std::size_t> active_region_index() const noexcept { return active_region_index_; }
        [[nodiscard]] const peelf::ModuleInfo* active_module() const noexcept;
        [[nodiscard]] const peelf::MemoryRegion* active_region() const noexcept;

        // Unified symbol & function indices (PE/ELF symbols, imports, exports, .pdata, call targets, PDB/DWARF symbols).
        [[nodiscard]] const SymbolIndex& symbol_index() const noexcept { return symbol_index_; }
        [[nodiscard]] const FunctionIndex& function_index() const noexcept { return function_index_; }
        void add_debug_symbols(std::span<const DebugSymbol> symbols);
        void apply_debug_symbol_result(const DebugSymbolLoadResult& result);
        [[nodiscard]] std::span<const DataTypeRecord> debug_types() const noexcept { return active_debug_types_; }
        [[nodiscard]] std::span<const SourceLineMapping> source_lines() const noexcept { return active_source_lines_; }
        [[nodiscard]] const SourceLineMapping* find_source_line(std::uint64_t virtual_address,
                                                                std::uint64_t max_distance = 64) const noexcept;
        [[nodiscard]] std::span<const AppliedStructureBinding> applied_structures() const noexcept {
            return applied_structures_;
        }
        void add_applied_structure(AppliedStructureBinding binding);
        void remove_applied_structure(std::size_t index);
        void clear_applied_structures() noexcept { applied_structures_.clear(); }
        [[nodiscard]] bool demangle_symbols() const noexcept { return demangle_symbols_; }
        void set_demangle_symbols(bool enabled) noexcept { demangle_symbols_ = enabled; }
        void set_analysis_thumb_mode(bool thumb_mode);
        [[nodiscard]] std::string resolve_address_symbol(std::uint64_t virtual_address) const;

        // Live process & thread pause/resume, register context, stack unwinding, and TLS inspection.
        [[nodiscard]] bool is_process_suspended() const noexcept;
        [[nodiscard]] peelf::SubsystemStatus suspend_process();
        [[nodiscard]] peelf::SubsystemStatus resume_process();
        [[nodiscard]] peelf::SubsystemStatus suspend_thread(peelf::ThreadId tid);
        [[nodiscard]] peelf::SubsystemStatus resume_thread(peelf::ThreadId tid);
        [[nodiscard]] peelf::ForgivingValue<std::vector<peelf::ThreadInfo>> refresh_threads();
        [[nodiscard]] const std::vector<peelf::ThreadInfo>& threads() const noexcept { return threads_; }
        [[nodiscard]] const peelf::SubsystemStatus& threads_status() const noexcept { return threads_status_; }
        [[nodiscard]] std::optional<peelf::ThreadId> selected_thread_id() const noexcept { return selected_tid_; }
        void select_thread(peelf::ThreadId tid);
        void refresh_selected_thread_inspection();
        [[nodiscard]] const peelf::ForgivingValue<peelf::ThreadContext>& selected_thread_context() const noexcept {
            return selected_thread_context_;
        }
        [[nodiscard]] const peelf::ThreadStackSnapshot& selected_thread_stack() const noexcept {
            return selected_thread_stack_;
        }
        [[nodiscard]] const peelf::ThreadLocalSnapshot& selected_thread_locals() const noexcept {
            return selected_thread_locals_;
        }

        // Endian-aware memory & file search (Heap, Selected Region, Active Module, All Readable / Full File).
        [[nodiscard]] peelf::Result<peelf::MemorySearchReport> search_memory(
            const peelf::MemorySearchQuery& query) const;

        // Coherent PEB/TEB + Linux runtime structures, harvested header flags, and VEH/SEH/atexit/signal handlers.
        void refresh_runtime_and_handlers();
        [[nodiscard]] const peelf::HeaderFlagsReport& header_flags() const noexcept { return header_flags_; }
        [[nodiscard]] const peelf::ProcessEnvironmentSnapshot& process_environment() const noexcept {
            return process_env_;
        }
        [[nodiscard]] const peelf::ThreadEnvironmentSnapshot& thread_environment() const noexcept {
            return thread_env_;
        }
        [[nodiscard]] const peelf::HandlersReport& handlers_report() const noexcept { return handlers_report_; }

        // Read-only lazy/manual Process Explorer & System Informer user-mode telemetry.
        void refresh_process_internals();
        [[nodiscard]] bool has_process_internals() const noexcept { return process_internals_loaded_; }
        [[nodiscard]] const peelf::ProcessInternalsSnapshot& process_internals() const noexcept {
            return process_internals_;
        }

        // Unified window addressing:
        // - Static file: view_base_address() == 0, view_size() == file size, offset == file offset.
        // - Live process: view_base_address() == module/region start VA, offset == VA - view_base_address().
        [[nodiscard]] std::uint64_t view_base_address() const noexcept;
        [[nodiscard]] std::uint64_t view_size() const noexcept;
        [[nodiscard]] std::optional<std::uint64_t> offset_to_virtual_address(std::uint64_t offset) const noexcept;
        [[nodiscard]] std::optional<std::uint64_t> virtual_address_to_offset(std::uint64_t virtual_address) const noexcept;

        [[nodiscard]] peelf::Result<peelf::MemorySample> read_window_sample(std::uint64_t offset,
                                                                            std::uint64_t size) const;
        [[nodiscard]] peelf::Result<std::vector<std::uint8_t>> read_effective_bytes(std::uint64_t offset,
                                                                                    std::uint64_t size) const;
        [[nodiscard]] peelf::Result<std::vector<std::uint8_t>> read_virtual_bytes(std::uint64_t virtual_address,
                                                                                  std::uint64_t size) const;

        [[nodiscard]] peelf::Result<void> apply_patch_bytes(std::uint64_t offset,
                                                            std::span<const std::uint8_t> bytes,
                                                            std::string label);
        [[nodiscard]] peelf::Result<void> stage_patch_at_va(std::uint64_t virtual_address,
                                                            std::span<const std::uint8_t> bytes,
                                                            std::string label);
        [[nodiscard]] peelf::Result<void> undo_patch();
        [[nodiscard]] peelf::Result<void> redo_patch();
        void discard_staged_patches() noexcept;

        // Explicit live RAM commit & revert (no-op / error when not attached to a live process).
        [[nodiscard]] peelf::Result<std::size_t> commit_patches_to_process(
            peelf::MemoryWriteOptions options = {.allow_protection_override = true});
        [[nodiscard]] peelf::Result<std::size_t> revert_committed_patches(
            peelf::MemoryWriteOptions options = {.allow_protection_override = true});
        [[nodiscard]] peelf::Result<void> revert_committed_patch_at(
            std::uint64_t virtual_address,
            std::uint64_t size,
            peelf::MemoryWriteOptions options = {.allow_protection_override = true});

        [[nodiscard]] peelf::Result<void> save_patched_as(const std::filesystem::path& output_path,
                                                          bool overwrite = false) const;

        [[nodiscard]] std::vector<peelf::PatchInterval> changed_intervals() const;
        [[nodiscard]] std::vector<peelf::PatchInterval> staged_live_patches() const;
        [[nodiscard]] std::vector<peelf::PatchInterval> committed_live_patches() const;
        [[nodiscard]] BytePatchState byte_patch_state_at_offset(std::uint64_t offset) const noexcept;
        peelf::Result<void> apply_patch_set(std::span<const peelf::PatchInterval> patches);
        [[nodiscard]] std::uint64_t edit_revision() const noexcept { return edit_revision_; }
        [[nodiscard]] const std::string& content_sha256() const;

    private:
        BinarySourceKind source_kind_ = BinarySourceKind::None;
        LiveViewTargetKind live_target_kind_ = LiveViewTargetKind::None;
        BinaryFormat format_ = BinaryFormat::None;
        std::uint64_t edit_revision_ = 0;
        std::uint64_t content_generation_ = 0;
        peelf::Architecture architecture_ = peelf::Architecture::Unknown;
        peelf::Endianness endianness_ = peelf::Endianness::Little;

        FileInfo file_info_;
        std::vector<std::uint8_t> bytes_;
        std::vector<std::uint8_t> live_backing_file_bytes_;
        std::vector<std::uint8_t> live_module_snapshot_bytes_;
        std::vector<std::uint8_t> live_pe_backing_bytes_;
        std::vector<SectionInfo> sections_;
        std::unique_ptr<PeModel> pe_;
        std::unique_ptr<peelf::IBinaryImage> image_;
        std::optional<peelf::PagedBinaryImage> editable_image_;
        SymbolIndex symbol_index_;
        FunctionIndex function_index_;
        bool analysis_thumb_mode_ = false;
        bool demangle_symbols_ = true;
        std::map<std::string, std::vector<DebugSymbol>> debug_symbols_by_key_;
        std::map<std::string, std::vector<DataTypeRecord>> debug_types_by_key_;
        std::map<std::string, std::vector<SourceLineMapping>> source_lines_by_key_;
        std::set<std::string> auto_loaded_debug_keys_;
        std::vector<DataTypeRecord> active_debug_types_;
        std::vector<SourceLineMapping> active_source_lines_;
        std::vector<AppliedStructureBinding> applied_structures_;

        std::shared_ptr<peelf::IProcessBackend> backend_;
        std::unique_ptr<peelf::IProcessSession> session_;
        std::optional<std::filesystem::path> resolved_exe_path_;
        std::vector<peelf::MemoryRegion> regions_;
        peelf::ForgivingValue<peelf::ProcessMemorySummary> memory_summary_;
        std::vector<peelf::AddressSpaceCluster> address_space_clusters_;
        std::vector<peelf::ModuleInfo> modules_;
        std::optional<std::size_t> active_module_index_;
        std::optional<std::size_t> active_region_index_;
        std::uint64_t live_window_base_ = 0;
        std::uint64_t live_window_size_ = 0;
        peelf::LiveMemoryPatchSpace live_patches_;

        // Live thread, stack, TLS, runtime structures, header flags, and handlers snapshots.
        std::vector<peelf::ThreadInfo> threads_;
        peelf::SubsystemStatus threads_status_;
        std::optional<peelf::ThreadId> selected_tid_;
        peelf::ForgivingValue<peelf::ThreadContext> selected_thread_context_;
        peelf::ThreadStackSnapshot selected_thread_stack_;
        peelf::ThreadLocalSnapshot selected_thread_locals_;
        peelf::HeaderFlagsReport header_flags_;
        peelf::ProcessEnvironmentSnapshot process_env_;
        peelf::ThreadEnvironmentSnapshot thread_env_;
        peelf::HandlersReport handlers_report_;
        peelf::ProcessInternalsSnapshot process_internals_{};
        bool process_internals_loaded_{false};
        peelf::ThreadCpuTracker thread_cpu_tracker_{};

        mutable std::string last_diagnostic_;
        mutable std::string cached_content_sha256_;
        mutable std::uint64_t cached_sha256_generation_ = std::numeric_limits<std::uint64_t>::max();
        mutable std::uint64_t cached_sha256_revision_ = std::numeric_limits<std::uint64_t>::max();

        void reset_all();
        [[nodiscard]] std::string current_debug_symbol_key() const;
        void store_debug_symbol_result_for_key(const std::string& key, const DebugSymbolLoadResult& result);
        bool auto_load_debug_info_for_current_image(const std::filesystem::path& image_path);
        void rebuild_symbol_index();
        void load_live_module_backing_bytes(const peelf::ModuleInfo& module);
        bool load_pe(const std::string& path);
        bool load_elf(const std::string& path);
        void populate_live_pe_legacy_model(const peelf::ModuleInfo& module);
    };

} // namespace viewer
