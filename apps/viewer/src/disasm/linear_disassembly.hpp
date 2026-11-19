#pragma once

#include "analysis/reference_index.hpp"
#include "analysis/function_index.hpp"
#include "disasm/disassembler.hpp"
#include "model/binary_model.hpp"
#include "navigation/viewer_navigation.hpp"
#include "symbols/debug_symbols.hpp"
#include "symbols/symbol_index.hpp"

#include <peelf/binary_image.hpp>

#include <cstddef>
#include <cstdint>
#include <functional>
#include <list>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

namespace viewer {

enum class AddressDisplayMode : std::uint8_t {
    VirtualAddress = 0,
    RelativeVirtualAddress = 1,
    FileOffset = 2,
};

[[nodiscard]] constexpr std::string_view to_string(AddressDisplayMode mode) noexcept {
    switch (mode) {
        case AddressDisplayMode::VirtualAddress:         return "VA";
        case AddressDisplayMode::RelativeVirtualAddress: return "RVA";
        case AddressDisplayMode::FileOffset:             return "File Offset";
    }
    return "VA";
}

struct HexAvailabilityStatus {
    bool available = true;
    std::string unavailable_reason{};
};

[[nodiscard]] std::string format_address_column(
    AddressDisplayMode mode,
    std::uint64_t file_offset,
    const peelf::IBinaryImage* image,
    std::optional<std::uint64_t> explicit_va = std::nullopt,
    std::optional<std::uint64_t> explicit_base_va = std::nullopt,
    bool is_64bit = true);

[[nodiscard]] std::string format_hex_row_address(
    AddressDisplayMode mode,
    std::uint64_t window_offset,
    const BinaryModel& model);

[[nodiscard]] std::string format_instruction_address(
    AddressDisplayMode mode,
    std::uint64_t instruction_va,
    std::optional<std::uint64_t> file_offset,
    std::uint64_t image_base,
    bool is_64bit);

[[nodiscard]] HexAvailabilityStatus evaluate_section_hex_availability(
    const peelf::Section& section,
    std::uint64_t available_file_size);

[[nodiscard]] HexAvailabilityStatus evaluate_hex_selection_availability(
    const BinaryModel& model,
    const ViewerSelection& selection);

struct LinearDisassemblySpan {
    std::string name{};
    std::uint64_t virtual_address = 0;
    std::optional<std::uint64_t> file_offset{};
    std::uint64_t byte_size = 0;
    bool executable = true;
    bool fallback_data = false;
};

struct ArmThumbRangeHint {
    std::uint64_t start_va = 0;
    std::uint64_t end_va = 0;
    bool thumb = false;
};

struct LinearDisassemblyRevision {
    std::uint64_t file_generation = 0;
    std::uint64_t edit_revision = 0;
    std::uint64_t snapshot_revision = 0;
    bool thumb_mode = false;
    bool thumb_mode_forced = false;

    [[nodiscard]] bool operator==(const LinearDisassemblyRevision&) const noexcept = default;
};

struct LinearDisassemblyOptions {
    std::size_t chunk_target_bytes = 16u * 1024u;
    std::size_t max_cached_chunks = 32u;
    std::size_t resync_lookbehind_bytes = 64u;
    std::size_t max_branch_lanes = 8u;
};

struct BranchArc {
    std::uint64_t source_va = 0;
    std::uint64_t target_va = 0;
    std::size_t source_row = 0;
    std::optional<std::size_t> target_row{};
    std::size_t lane = 0;
    bool is_conditional = false;
    bool is_upward = false;
    bool is_selected = false;
    bool target_offscreen_above = false;
    bool target_offscreen_below = false;
};

struct LinearMetadataContext {
    const SymbolIndex* symbols = nullptr;
    const FunctionIndex* functions = nullptr;
    const ReferenceIndex* references = nullptr;
    const AnnotationStore* annotations = nullptr;
    std::span<const SourceLineMapping> source_lines{};
    bool demangle_symbols = true;
    std::size_t max_xref_preview = 3u;
};

struct InstructionRowMetadata {
    bool has_header_banner = false;
    std::string symbol_name{};
    std::string raw_symbol_name{};
    std::uint64_t function_size = 0;
    std::string header_banner{};

    std::string user_label{};
    std::string user_comment{};

    std::size_t incoming_xref_count = 0;
    std::string xref_summary{};

    bool has_source_line = false;
    bool is_new_source_line = false;
    std::string source_file{};
    std::string source_full_path{};
    std::uint32_t source_line = 0;
    std::uint32_t source_column = 0;
    std::string source_tag{};
};

[[nodiscard]] std::vector<BranchArc> compute_branch_arcs(
    std::span<const Instruction> window_instructions,
    std::optional<std::uint64_t> selected_va = std::nullopt,
    std::size_t max_lanes = 8u,
    const FunctionIndex* functions = nullptr);

[[nodiscard]] InstructionRowMetadata describe_instruction_row(
    const Instruction& instruction,
    const LinearMetadataContext& context,
    std::optional<std::uint64_t> previous_instruction_va = std::nullopt);

[[nodiscard]] std::vector<ArmThumbRangeHint> extract_arm_thumb_hints(
    const peelf::IBinaryImage& image);

class LinearDisassemblyView {
public:
    using ByteReaderFn = std::function<std::size_t(std::uint64_t virtual_address,
                                                   std::span<std::uint8_t> out_buffer)>;

    explicit LinearDisassemblyView(LinearDisassemblyOptions options = {});

    void clear() noexcept;

    void set_options(LinearDisassemblyOptions options);
    [[nodiscard]] const LinearDisassemblyOptions& options() const noexcept { return options_; }

    bool configure_synthetic(
        Architecture arch,
        Endianness endian,
        std::span<const LinearDisassemblySpan> spans,
        ByteReaderFn reader,
        std::span<const std::uint64_t> symbol_boundaries = {},
        std::span<const ArmThumbRangeHint> arm_hints = {},
        LinearDisassemblyRevision revision = {});

    bool configure_image(
        const peelf::IBinaryImage& image,
        std::span<const std::uint8_t> file_bytes,
        const SymbolIndex* symbols = nullptr,
        const FunctionIndex* functions = nullptr,
        LinearDisassemblyRevision revision = {});

    bool sync_with_model(
        const BinaryModel& model,
        bool thumb_mode,
        bool force_thumb_override = false);

    void set_fallback_span(std::optional<LinearDisassemblySpan> fallback_span);
    void clear_fallback_span() noexcept;
    [[nodiscard]] bool has_fallback_span() const noexcept { return fallback_span_.has_value(); }

    void set_thumb_mode(bool enable, bool force_override = true);
    void clear_thumb_mode_override();
    [[nodiscard]] bool thumb_mode() const noexcept { return revision_.thumb_mode; }
    [[nodiscard]] bool thumb_mode_forced() const noexcept { return revision_.thumb_mode_forced; }
    [[nodiscard]] bool resolve_thumb_at_address(std::uint64_t virtual_address) const noexcept;

    void update_revision(LinearDisassemblyRevision revision);
    [[nodiscard]] const LinearDisassemblyRevision& revision() const noexcept { return revision_; }

    [[nodiscard]] bool empty() const noexcept { return chunks_.empty(); }
    [[nodiscard]] Architecture architecture() const noexcept { return arch_; }
    [[nodiscard]] Endianness endianness() const noexcept { return endian_; }

    [[nodiscard]] std::span<const LinearDisassemblySpan> spans() const noexcept { return active_spans_; }
    [[nodiscard]] const LinearDisassemblySpan* span_for_address(std::uint64_t virtual_address) const noexcept;
    [[nodiscard]] bool contains_executable_address(std::uint64_t virtual_address) const noexcept;

    [[nodiscard]] std::size_t total_rows() const noexcept;
    [[nodiscard]] std::size_t total_chunk_count() const noexcept { return chunks_.size(); }
    [[nodiscard]] std::uint64_t chunk_start_address(std::size_t chunk_index) const noexcept {
        return chunk_index < chunks_.size() ? chunks_[chunk_index].start_va : 0u;
    }
    [[nodiscard]] std::size_t cached_chunk_count() const noexcept { return chunk_cache_.size(); }
    [[nodiscard]] std::size_t cache_hits() const noexcept { return cache_hits_; }
    [[nodiscard]] std::size_t cache_misses() const noexcept { return cache_misses_; }
    [[nodiscard]] std::size_t cache_evictions() const noexcept { return cache_evictions_; }

    void prepare_row_range(std::size_t start_row, std::size_t row_count);
    [[nodiscard]] const Instruction* instruction_at_row(std::size_t global_row);
    [[nodiscard]] std::vector<Instruction> collect_rows(std::size_t start_row, std::size_t row_count);

    [[nodiscard]] std::optional<std::size_t> find_row_for_address(std::uint64_t virtual_address);
    [[nodiscard]] std::optional<Instruction> find_instruction_at_address(std::uint64_t virtual_address);
    [[nodiscard]] std::vector<Instruction> decode_window_from_address(
        std::uint64_t virtual_address,
        std::size_t max_instructions);
    [[nodiscard]] std::vector<Instruction> decode_address_range(
        std::uint64_t start_va,
        std::uint64_t end_va);

private:
    struct ChunkDescriptor {
        std::size_t span_index = 0;
        std::uint64_t start_va = 0;
        std::uint64_t end_va = 0;
        std::optional<std::uint64_t> resolved_start_va{};
        std::size_t row_count = 0;
        bool exact_row_count = false;
    };

    struct CachedChunk {
        std::uint64_t decoded_start_va = 0;
        std::vector<Instruction> instructions{};
        std::list<std::size_t>::iterator lru_it{};
    };

    void rebuild_partitions();
    void recompute_row_prefix_sums() noexcept;
    void invalidate_decoded_cache(bool reset_row_counts) noexcept;
    [[nodiscard]] std::size_t estimated_rows_for_bytes(std::uint64_t byte_count,
                                                       std::uint64_t start_va) const noexcept;
    [[nodiscard]] std::size_t alignment_for_address(std::uint64_t virtual_address) const noexcept;
    [[nodiscard]] std::uint64_t normalize_lookup_address(std::uint64_t virtual_address) const noexcept;
    [[nodiscard]] std::optional<std::size_t> chunk_index_for_row(std::size_t global_row) const noexcept;
    [[nodiscard]] std::optional<std::size_t> chunk_index_for_address(std::uint64_t virtual_address) const noexcept;
    const CachedChunk* ensure_chunk_decoded(std::size_t chunk_index);
    [[nodiscard]] std::uint64_t determine_chunk_effective_start(std::size_t chunk_index);
    [[nodiscard]] std::vector<Instruction> decode_range_raw(
        std::uint64_t start_va,
        std::uint64_t stop_va,
        std::uint64_t span_end_va,
        std::uint64_t* out_end_va) const;

    LinearDisassemblyOptions options_{};
    Architecture arch_ = Architecture::X86_64;
    Endianness endian_ = Endianness::Little;
    bool configured_ = false;
    LinearDisassemblyRevision revision_{};

    ByteReaderFn byte_reader_{};
    std::vector<LinearDisassemblySpan> base_spans_{};
    std::optional<LinearDisassemblySpan> fallback_span_{};
    std::vector<LinearDisassemblySpan> active_spans_{};
    std::vector<std::uint64_t> symbol_boundaries_{};
    std::vector<ArmThumbRangeHint> arm_hints_{};

    std::vector<ChunkDescriptor> chunks_{};
    std::vector<std::size_t> chunk_row_offsets_{};

    std::list<std::size_t> lru_order_{};
    std::unordered_map<std::size_t, CachedChunk> chunk_cache_{};
    std::size_t cache_hits_ = 0;
    std::size_t cache_misses_ = 0;
    std::size_t cache_evictions_ = 0;

    std::uint64_t synced_model_identity_ = 0;
};

} // namespace viewer
