#pragma once
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <functional>
#include <limits>
#include <map>
#include <memory>
#include <optional>
#include <set>
#include <span>
#include <string>
#include <vector>

#include "analysis/function_index.hpp"
#include "symbols/data_types.hpp"
#include "symbols/debug_symbols.hpp"
#include "symbols/symbol_index.hpp"

#include <peelf/binary_image.hpp>
#include <peelf/capability_matrix.hpp>
#include <peelf/crash_dump.hpp>
#include <peelf/debugger.hpp>
#include <peelf/endian_reader.hpp>
#include <peelf/executable_settings.hpp>
#include <peelf/execution_timeline.hpp>
#include <peelf/forgiving.hpp>
#include <peelf/gdb_remote.hpp>
#include <peelf/handlers.hpp>
#include <peelf/memory_search.hpp>
#include <peelf/patch_bundle.hpp>
#include <peelf/patching.hpp>
#include <peelf/process.hpp>
#include <peelf/process_internals.hpp>
#include <peelf/process_snapshot.hpp>
#include <peelf/provenance.hpp>
#include <peelf/runtime_structures.hpp>
#include <peelf/scripting.hpp>
#include <peelf/security_audit.hpp>
#include <peelf/stack_tls.hpp>

namespace viewer {

    enum class BinaryFormat {
        None,
        PE,
        ELF,
        MachO
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

    struct ResolvedSymbolInfo {
        std::string display_label{};
        std::string symbol_name{};
        std::string module_name{};
        SymbolSource source{SymbolSource::ImageSymbol};
        std::uint64_t symbol_va{0};
        std::uint64_t offset{0};
        bool heuristic_discovered{false};
        bool backing_identity_verified{true};
    };

    enum class AsyncScriptStatus : std::uint8_t {
        Succeeded = 0,
        Cancelled = 1,
        Failed = 2,
        StaleDiscarded = 3,
    };

    struct ScriptExecutionStamp {
        std::uint64_t content_generation{0};
        std::uint64_t edit_revision{0};
        std::uint64_t annotation_revision{0};

        auto operator<=>(const ScriptExecutionStamp&) const = default;
    };

    struct ScriptMutationEligibility {
        bool can_mutate_target{false};
        std::string reason{};
    };

    struct AsyncScriptOutcome {
        AsyncScriptStatus status{AsyncScriptStatus::Failed};
        ScriptExecutionStamp expected_stamp{};
        bool allow_mutations_effective{false};
        bool mutations_applied_to_model{false};
        std::string apply_diagnostic{};
        peelf::ScriptExecutionResult script_result{};
        peelf::ProjectWorkspace committed_workspace{};
    };

    class BinaryModel {
    public:
        BinaryModel();
        ~BinaryModel() noexcept;
        BinaryModel(const BinaryModel&) = delete;
        BinaryModel& operator=(const BinaryModel&) = delete;
        BinaryModel(BinaryModel&&) noexcept;
        BinaryModel& operator=(BinaryModel&&) noexcept;

        bool load_file(const std::string& path);

        // Live process inspection & attach API (100% strictly read-only by default).
        void set_process_backend(std::shared_ptr<peelf::IProcessBackend> backend);
        [[nodiscard]] peelf::IProcessBackend& process_backend();
        [[nodiscard]] peelf::Result<std::vector<peelf::ProcessInfo>> list_processes();
        [[nodiscard]] peelf::Result<void> attach_process(peelf::ProcessId pid);
        [[nodiscard]] peelf::Result<void> attach_session(std::unique_ptr<peelf::IProcessSession> session);
        void detach_process();
        [[nodiscard]] peelf::Result<void> refresh_process_map();

        // Explicit opt-in active debugger session API (uses IDebugSession breakpoints & execution control).
        void set_debug_backend(std::shared_ptr<peelf::debugger::IDebugBackend> backend);
        [[nodiscard]] peelf::debugger::IDebugBackend& debug_backend();
        [[nodiscard]] peelf::Result<void> launch_debug_process(
            const std::filesystem::path& executable,
            std::span<const std::string> args = {},
            const std::filesystem::path& working_dir = {});
        [[nodiscard]] peelf::Result<void> attach_debug_process(peelf::ProcessId pid);
        [[nodiscard]] peelf::Result<void> attach_debug_session(
            std::unique_ptr<peelf::debugger::IDebugSession> debug_session,
            bool launched_by_session = false);

        // Remote GDB RSP / QEMU / kgdb / OpenOCD connection API
        // (strictly read-only by default; opt-in debugger requires ExplicitDebugConsent).
        [[nodiscard]] peelf::Result<void> connect_gdb_remote_readonly(
            const peelf::GdbRemoteOpenOptions& options);
        [[nodiscard]] peelf::Result<void> connect_gdb_remote_readonly(
            std::unique_ptr<peelf::IRspTransport> transport,
            const peelf::GdbRemoteOpenOptions& options = {});
        [[nodiscard]] peelf::Result<void> connect_gdb_remote_debug(
            const peelf::GdbRemoteOpenOptions& options,
            peelf::ExplicitDebugConsent consent);
        [[nodiscard]] peelf::Result<void> connect_gdb_remote_debug(
            std::unique_ptr<peelf::IRspTransport> transport,
            peelf::ExplicitDebugConsent consent,
            const peelf::GdbRemoteOpenOptions& options = {});

        [[nodiscard]] bool is_debug_session() const noexcept { return debug_session_ != nullptr; }
        [[nodiscard]] peelf::debugger::IDebugSession* debug_session() noexcept { return debug_session_.get(); }
        [[nodiscard]] const peelf::debugger::IDebugSession* debug_session() const noexcept {
            return debug_session_.get();
        }
        [[nodiscard]] std::optional<std::uint64_t> sync_debugger_stop_state();
        void refresh_debug_breakpoints();
        [[nodiscard]] std::span<const peelf::debugger::BreakpointDescriptor> debug_breakpoints() const noexcept {
            return debug_breakpoints_;
        }
        [[nodiscard]] const peelf::debugger::BreakpointDescriptor* find_breakpoint_at(
            std::uint64_t virtual_address) const noexcept;
        [[nodiscard]] peelf::Result<bool> toggle_software_breakpoint(
            std::uint64_t virtual_address,
            std::string label = {});
        [[nodiscard]] bool has_debug_register_changed(
            std::string_view reg_name,
            std::uint64_t current_value) const noexcept;
        [[nodiscard]] std::optional<std::uint64_t> previous_debug_register_value(
            std::string_view reg_name) const noexcept;

        [[nodiscard]] peelf::Result<void> select_process_module(std::size_t module_index);
        [[nodiscard]] peelf::Result<void> select_memory_region(std::size_t region_index,
                                                               bool prefer_module_context = true);
        [[nodiscard]] std::optional<std::uint64_t> navigate_to_virtual_address(std::uint64_t virtual_address);

        [[nodiscard]] bool has_file() const { return format_ != BinaryFormat::None || is_live_process(); }
        [[nodiscard]] bool has_data_window() const noexcept { return view_size() > 0; }
        [[nodiscard]] bool is_live_process() const noexcept {
            return source_kind_ == BinarySourceKind::LiveProcess && session_ != nullptr;
        }
        [[nodiscard]] bool is_crash_dump() const noexcept {
            return is_live_process() && session_->is_crash_dump();
        }
        [[nodiscard]] const peelf::CrashDumpSummary* crash_dump_summary() const noexcept;
        [[nodiscard]] bool is_read_only() const noexcept { return is_live_process(); }
        [[nodiscard]] BinarySourceKind source_kind() const noexcept { return source_kind_; }
        [[nodiscard]] LiveViewTargetKind live_target_kind() const noexcept { return live_target_kind_; }
        [[nodiscard]] BinaryFormat format() const { return format_; }
        [[nodiscard]] peelf::Architecture architecture() const noexcept { return architecture_; }
        [[nodiscard]] peelf::Endianness endianness() const noexcept { return endianness_; }
        [[nodiscard]] peelf::TargetLayout target_layout() const noexcept;

        [[nodiscard]] const FileInfo& file_info() const { return file_info_; }
        [[nodiscard]] const peelf::BinaryContainerInfo& container_info() const noexcept { return container_info_; }
        [[nodiscard]] std::size_t active_slice_index() const noexcept { return active_slice_index_; }
        [[nodiscard]] bool is_universal_container() const noexcept {
            return !is_live_process() && container_info_.is_universal_container &&
                   container_info_.slices.size() > 1u;
        }
        [[nodiscard]] bool select_container_slice(std::size_t slice_index);
        [[nodiscard]] const std::vector<std::uint8_t>& bytes() const { return bytes_; }
        [[nodiscard]] std::span<const std::uint8_t> analysis_image_bytes() const noexcept;
        [[nodiscard]] std::uint64_t analysis_image_size() const noexcept;
        [[nodiscard]] const std::vector<SectionInfo>& sections() const { return sections_; }
        [[nodiscard]] const std::string& last_diagnostic() const noexcept { return last_diagnostic_; }

        // Unified core image (format-agnostic identity). Non-null once a PE or ELF
        // file or live module parses.
        [[nodiscard]] const peelf::IBinaryImage* image() const { return image_.get(); }
        [[nodiscard]] const peelf::PagedBinaryImage* editable_image() const {
            return (!is_live_process() && editable_image_) ? &*editable_image_ : nullptr;
        }

        // Live process state accessors.
        [[nodiscard]] const peelf::IProcessSession* process_session() const noexcept { return session_.get(); }
        [[nodiscard]] peelf::IProcessSession* process_session() noexcept { return session_.get(); }
        [[nodiscard]] std::shared_ptr<peelf::IProcessSession> shared_process_session() const noexcept {
            return session_;
        }
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
        void clear_applied_structures() noexcept {
            if (!applied_structures_.empty()) {
                applied_structures_.clear();
                ++structure_binding_revision_;
            }
        }
        [[nodiscard]] std::uint64_t structure_binding_revision() const noexcept {
            return structure_binding_revision_;
        }

        [[nodiscard]] std::span<const Bookmark> bookmarks() const noexcept { return bookmarks_; }
        void add_or_update_bookmark(Bookmark bookmark);
        bool remove_bookmark_at(std::uint64_t address, bool is_file_offset = false);
        void remove_bookmark_index(std::size_t index);
        void clear_bookmarks() noexcept {
            if (!bookmarks_.empty()) {
                bookmarks_.clear();
                ++bookmark_revision_;
                ++annotation_revision_;
            }
        }
        [[nodiscard]] const Bookmark* find_bookmark(std::uint64_t address,
                                                    bool is_file_offset = false) const noexcept;
        [[nodiscard]] std::uint64_t bookmark_revision() const noexcept { return bookmark_revision_; }
        [[nodiscard]] std::uint64_t annotation_revision() const noexcept { return annotation_revision_; }
        void bump_annotation_revision() noexcept { ++annotation_revision_; }
        void cancel_and_join_workers() noexcept;
        void set_session_teardown_hook(std::function<void()> hook) {
            teardown_guard_.hook = std::move(hook);
        }
        [[nodiscard]] bool demangle_symbols() const noexcept { return demangle_symbols_; }
        void set_demangle_symbols(bool enabled) noexcept { demangle_symbols_ = enabled; }
        [[nodiscard]] bool analysis_thumb_mode() const noexcept { return analysis_thumb_mode_; }
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
        [[nodiscard]] const peelf::SecurityAuditReport& security_audit() const noexcept { return security_audit_; }

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
        [[nodiscard]] bool is_byte_patched(std::uint64_t offset) const noexcept {
            return byte_patch_state_at_offset(offset) != BytePatchState::Unchanged;
        }
        [[nodiscard]] peelf::Result<void> apply_patch_set(std::span<const peelf::PatchInterval> patches);
        [[nodiscard]] peelf::Result<void> reset_static_patches_to_baseline();

        // Reusable JSON Patch Bundles (.pepatch.json) — static binaries only; strictly rejected on live processes.
        void record_patch_metadata(std::uint64_t offset,
                                   std::string label,
                                   std::optional<std::string> asm_source = std::nullopt);
        [[nodiscard]] peelf::Result<peelf::PatchBundle> export_patch_bundle(
            std::string name = {},
            std::string description = {}) const;
        [[nodiscard]] peelf::Result<peelf::PatchBundlePreview> preview_patch_bundle(
            const peelf::PatchBundle& bundle,
            const peelf::PatchBundleApplyOptions& options = {}) const;
        [[nodiscard]] peelf::Result<void> apply_patch_bundle(
            const peelf::PatchBundle& bundle,
            const peelf::PatchBundleApplyOptions& options = {});

        [[nodiscard]] std::uint64_t edit_revision() const noexcept { return edit_revision_; }
        [[nodiscard]] std::uint64_t content_generation() const noexcept { return content_generation_; }
        [[nodiscard]] std::uint64_t active_revision_token() const noexcept {
            return (content_generation_ << 32u) ^ edit_revision_;
        }
        [[nodiscard]] const std::string& content_sha256() const;

        // Target capability matrix & per-collection provenance envelope (WU-21).
        [[nodiscard]] peelf::Observed<ResolvedSymbolInfo> resolve_symbol_with_provenance(
            std::uint64_t virtual_address) const;
        [[nodiscard]] const peelf::TargetProfile& target_profile() const noexcept {
            return target_profile_;
        }
        [[nodiscard]] const peelf::ProviderFacts& provider_facts() const noexcept {
            return provider_facts_;
        }
        void set_provider_facts(peelf::ProviderFacts facts) noexcept;
        [[nodiscard]] const peelf::TargetCapabilityMatrix& capability_matrix() const noexcept {
            return capability_matrix_;
        }
        [[nodiscard]] const peelf::TargetInstanceId& target_instance_id() const noexcept {
            return target_instance_id_;
        }
        [[nodiscard]] const peelf::BackingIdentityMatchResult& backing_identity_status() const noexcept {
            return backing_identity_status_;
        }
        [[nodiscard]] const peelf::CaptureStamp& static_image_stamp() const noexcept {
            return static_image_stamp_;
        }
        [[nodiscard]] const peelf::CaptureStamp& memory_map_stamp() const noexcept {
            return memory_map_stamp_;
        }
        [[nodiscard]] const peelf::CaptureStamp& threads_stamp() const noexcept {
            return threads_stamp_;
        }
        [[nodiscard]] const peelf::CaptureStamp& selected_thread_stamp() const noexcept {
            return selected_thread_stamp_;
        }
        [[nodiscard]] const peelf::CaptureStamp& runtime_stamp() const noexcept {
            return runtime_stamp_;
        }
        [[nodiscard]] const peelf::CaptureStamp& process_internals_stamp() const noexcept {
            return process_internals_stamp_;
        }
        [[nodiscard]] std::uint64_t current_capture_revision() const noexcept {
            return next_capture_revision_;
        }
        [[nodiscard]] const peelf::ExecutableSettingsReport& executable_settings() const noexcept {
            return executable_settings_;
        }

        // Timestamped ProcessStateSnapshot capture, interval/identity SnapshotDiff,
        // and session-scoped environment redaction opt-in (WU-23).
        [[nodiscard]] peelf::EnvironmentRedactionPolicy environment_redaction_policy() const noexcept {
            return environment_redaction_policy_;
        }
        void set_environment_redaction_policy(peelf::EnvironmentRedactionPolicy policy);
        [[nodiscard]] peelf::Result<std::size_t> capture_snapshot(bool pause_during_capture = false);
        [[nodiscard]] peelf::Result<void> diff_snapshots(std::size_t before_index, std::size_t after_index);
        void clear_snapshots() noexcept;
        [[nodiscard]] std::span<const peelf::ProcessStateSnapshot> captured_snapshots() const noexcept {
            return captured_snapshots_;
        }
        [[nodiscard]] const std::optional<peelf::SnapshotDiff>& latest_snapshot_diff() const noexcept {
            return latest_snapshot_diff_;
        }

        // Multi-thread execution & event timeline (WU-24).
        [[nodiscard]] const peelf::ExecutionTimeline& execution_timeline() const noexcept {
            return execution_timeline_;
        }
        [[nodiscard]] peelf::ExecutionTimeline& execution_timeline() noexcept {
            return execution_timeline_;
        }
        void clear_execution_timeline() noexcept;
        std::size_t sync_debugger_timeline_events();
        [[nodiscard]] peelf::Result<std::size_t> record_timeline_snapshot_delta(
            bool pause_during_capture = false);

        // Sandboxed Lua 5.4 async script execution & UI-thread transactional harvest (WU-28b).
        [[nodiscard]] ScriptMutationEligibility script_mutation_eligibility() const;
        [[nodiscard]] ScriptExecutionStamp current_script_stamp() const noexcept {
            return ScriptExecutionStamp{
                .content_generation = content_generation_,
                .edit_revision = edit_revision_,
                .annotation_revision = annotation_revision_,
            };
        }
        [[nodiscard]] peelf::Result<void> start_script_execution(
            std::string script_source,
            peelf::ScriptLimits limits = {},
            bool request_allow_mutations = false,
            peelf::ProjectWorkspace initial_workspace = {},
            std::string chunk_name = "=panel_script");
        void cancel_script_execution() noexcept;
        [[nodiscard]] bool is_script_running() const noexcept;
        void wait_for_script_idle() noexcept;
        [[nodiscard]] std::optional<AsyncScriptOutcome> harvest_script_execution();
        [[nodiscard]] const std::optional<AsyncScriptOutcome>& last_script_outcome() const noexcept {
            return last_script_outcome_;
        }
        void clear_last_script_outcome() noexcept { last_script_outcome_.reset(); }

    private:
        class AsyncScriptRunner;
        struct PreMoveTeardown {
            BinaryModel* owner{nullptr};
            std::function<void()> hook{};

            PreMoveTeardown() = default;
            explicit PreMoveTeardown(BinaryModel* self) noexcept : owner(self) {}
            PreMoveTeardown(const PreMoveTeardown&) = delete;
            PreMoveTeardown& operator=(const PreMoveTeardown&) = delete;
            PreMoveTeardown(PreMoveTeardown&& other) noexcept;
            PreMoveTeardown& operator=(PreMoveTeardown&& other) noexcept;
            ~PreMoveTeardown() = default;
        };

        void release_live_sessions() noexcept;
        void sync_live_executable_settings();
        PreMoveTeardown teardown_guard_{this};
        BinarySourceKind source_kind_ = BinarySourceKind::None;
        LiveViewTargetKind live_target_kind_ = LiveViewTargetKind::None;
        BinaryFormat format_ = BinaryFormat::None;
        std::uint64_t edit_revision_ = 0;
        std::uint64_t content_generation_ = 0;
        peelf::Architecture architecture_ = peelf::Architecture::Unknown;
        peelf::Endianness endianness_ = peelf::Endianness::Little;

        FileInfo file_info_;
        peelf::BinaryContainerInfo container_info_{};
        std::size_t active_slice_index_{0};
        std::vector<std::uint8_t> bytes_;
        std::vector<std::uint8_t> live_backing_file_bytes_;
        std::vector<std::uint8_t> live_module_snapshot_bytes_;
        std::vector<SectionInfo> sections_;
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
        struct PatchEntryMetadata {
            std::string label{};
            std::optional<std::string> asm_source{};
        };

        std::vector<AppliedStructureBinding> applied_structures_;
        std::vector<Bookmark> bookmarks_;
        std::map<std::uint64_t, PatchEntryMetadata> patch_metadata_by_offset_;
        std::uint64_t structure_binding_revision_ = 0;
        std::uint64_t bookmark_revision_ = 0;
        std::uint64_t annotation_revision_ = 0;

        std::shared_ptr<peelf::IProcessBackend> backend_;
        std::shared_ptr<peelf::debugger::IDebugBackend> debug_backend_;
        std::shared_ptr<peelf::debugger::IDebugSession> debug_session_;
        std::shared_ptr<peelf::IProcessSession> session_;
        std::vector<peelf::debugger::BreakpointDescriptor> debug_breakpoints_;
        std::uint64_t last_synced_debug_stop_revision_ = 0;
        std::map<std::string, std::uint64_t, std::less<>> previous_debug_registers_;
        std::map<std::string, std::uint64_t, std::less<>> current_debug_registers_;
        bool has_previous_debug_stop_ = false;
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
        peelf::SecurityAuditReport security_audit_;
        peelf::ExecutableSettingsReport executable_settings_{};
        peelf::EnvironmentRedactionPolicy environment_redaction_policy_{
            peelf::EnvironmentRedactionPolicy::RedactSensitiveDefault};
        bool launched_debug_session_{false};
        std::vector<peelf::ProcessStateSnapshot> captured_snapshots_{};
        std::optional<peelf::SnapshotDiff> latest_snapshot_diff_{};
        std::vector<std::uint64_t> timeline_proven_dynamic_bases_{};
        peelf::ProcessInternalsSnapshot process_internals_{};
        bool process_internals_loaded_{false};
        peelf::ThreadCpuTracker thread_cpu_tracker_{};

        peelf::ProviderFacts provider_facts_{peelf::ProviderFacts::detect_host_providers()};
        peelf::TargetProfile target_profile_{};
        peelf::TargetCapabilityMatrix capability_matrix_{
            peelf::capabilities_for(peelf::TargetProfile{}, provider_facts_)};
        peelf::TargetInstanceId target_instance_id_{};
        peelf::BackingIdentityMatchResult backing_identity_status_{};
        std::uint64_t next_capture_revision_{0};
        bool in_coordinated_attach_{false};
        peelf::CaptureStamp static_image_stamp_{};
        peelf::CaptureStamp memory_map_stamp_{};
        peelf::CaptureStamp threads_stamp_{};
        peelf::CaptureStamp selected_thread_stamp_{};
        peelf::CaptureStamp runtime_stamp_{};
        peelf::CaptureStamp process_internals_stamp_{};
        peelf::ExecutionTimeline execution_timeline_{};
        std::shared_ptr<peelf::DebugSessionTimelineSource> debug_timeline_source_{};
        std::unique_ptr<AsyncScriptRunner> script_runner_{};
        std::optional<AsyncScriptOutcome> last_script_outcome_{};

        mutable std::string last_diagnostic_;
        mutable std::string cached_content_sha256_;
        mutable std::uint64_t cached_sha256_generation_ = std::numeric_limits<std::uint64_t>::max();
        mutable std::uint64_t cached_sha256_revision_ = std::numeric_limits<std::uint64_t>::max();

        void reset_all();
        void reset_timeline_sources();
        void recompute_capabilities() noexcept;
        [[nodiscard]] peelf::CaptureStamp advance_live_capture_stamp(
            peelf::CaptureAvailability availability) noexcept;
        void mark_live_volatile_stamps_stale(bool include_paused_stamps) noexcept;
        [[nodiscard]] std::string current_debug_symbol_key() const;
        void store_debug_symbol_result_for_key(const std::string& key, const DebugSymbolLoadResult& result);
        bool auto_load_debug_info_for_current_image(const std::filesystem::path& image_path);
        void rebuild_symbol_index();
        void load_live_module_backing_bytes(const peelf::ModuleInfo& module);
        bool load_pe(const std::string& path);
        bool load_elf(const std::string& path);
        bool load_macho(const std::string& path);
    };

} // namespace viewer
