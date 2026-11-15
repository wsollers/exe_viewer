#pragma once
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <map>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <vector>

#include "pe_model.hpp"
#include "symbols/symbol_index.hpp"

#include <peelf/binary_image.hpp>
#include <peelf/patching.hpp>
#include <peelf/process.hpp>

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
        [[nodiscard]] BinarySourceKind source_kind() const noexcept { return source_kind_; }
        [[nodiscard]] LiveViewTargetKind live_target_kind() const noexcept { return live_target_kind_; }
        [[nodiscard]] BinaryFormat format() const { return format_; }
        [[nodiscard]] peelf::Architecture architecture() const noexcept { return architecture_; }
        [[nodiscard]] peelf::Endianness endianness() const noexcept { return endianness_; }

        [[nodiscard]] const FileInfo& file_info() const { return file_info_; }
        [[nodiscard]] const std::vector<std::uint8_t>& bytes() const { return bytes_; }
        [[nodiscard]] const std::vector<SectionInfo>& sections() const { return sections_; }
        [[nodiscard]] const std::string& last_diagnostic() const noexcept { return last_diagnostic_; }

        [[nodiscard]] const PeModel* pe() const { return pe_.get(); }

        // Unified core image (format-agnostic identity). Non-null once a PE or ELF
        // file or live module parses.
        [[nodiscard]] const peelf::IBinaryImage* image() const { return image_.get(); }
        [[nodiscard]] const peelf::PagedBinaryImage* editable_image() const {
            return editable_image_ ? &*editable_image_ : nullptr;
        }

        // Live process state accessors.
        [[nodiscard]] const peelf::IProcessSession* process_session() const noexcept { return session_.get(); }
        [[nodiscard]] const std::vector<peelf::MemoryRegion>& memory_regions() const noexcept { return regions_; }
        [[nodiscard]] const std::vector<peelf::ModuleInfo>& process_modules() const noexcept { return modules_; }
        [[nodiscard]] std::optional<std::size_t> active_module_index() const noexcept { return active_module_index_; }
        [[nodiscard]] std::optional<std::size_t> active_region_index() const noexcept { return active_region_index_; }
        [[nodiscard]] const peelf::ModuleInfo* active_module() const noexcept;
        [[nodiscard]] const peelf::MemoryRegion* active_region() const noexcept;

        // Unified symbol index (PE/ELF symbols, imports, exports, and rebased PDB debug symbols).
        [[nodiscard]] const SymbolIndex& symbol_index() const noexcept { return symbol_index_; }
        void add_debug_symbols(std::span<const DebugSymbol> symbols);

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

    private:
        BinarySourceKind source_kind_ = BinarySourceKind::None;
        LiveViewTargetKind live_target_kind_ = LiveViewTargetKind::None;
        BinaryFormat format_ = BinaryFormat::None;
        std::uint64_t edit_revision_ = 0;
        peelf::Architecture architecture_ = peelf::Architecture::Unknown;
        peelf::Endianness endianness_ = peelf::Endianness::Little;

        FileInfo file_info_;
        std::vector<std::uint8_t> bytes_;
        std::vector<std::uint8_t> live_pe_backing_bytes_;
        std::vector<SectionInfo> sections_;
        std::unique_ptr<PeModel> pe_;
        std::unique_ptr<peelf::IBinaryImage> image_;
        std::optional<peelf::PagedBinaryImage> editable_image_;
        SymbolIndex symbol_index_;
        std::map<std::string, std::vector<DebugSymbol>> debug_symbols_by_key_;

        std::shared_ptr<peelf::IProcessBackend> backend_;
        std::unique_ptr<peelf::IProcessSession> session_;
        std::vector<peelf::MemoryRegion> regions_;
        std::vector<peelf::ModuleInfo> modules_;
        std::optional<std::size_t> active_module_index_;
        std::optional<std::size_t> active_region_index_;
        std::uint64_t live_window_base_ = 0;
        std::uint64_t live_window_size_ = 0;
        peelf::LiveMemoryPatchSpace live_patches_;
        mutable std::string last_diagnostic_;

        void reset_all();
        [[nodiscard]] std::string current_debug_symbol_key() const;
        void rebuild_symbol_index();
        bool load_pe(const std::string& path);
        bool load_elf(const std::string& path);
        void populate_live_pe_legacy_model(const peelf::ModuleInfo& module);
    };

} // namespace viewer
