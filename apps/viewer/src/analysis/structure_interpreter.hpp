#pragma once

#include "symbols/data_types.hpp"

#include <peelf/binary_image.hpp>
#include <peelf/endian_reader.hpp>
#include <peelf/error.hpp>
#include <peelf/forgiving.hpp>
#include <peelf/process.hpp>

#include <cstddef>
#include <cstdint>
#include <functional>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

namespace viewer {

class BinaryModel;

enum class StructureSchemaOrigin : std::uint8_t {
    UserOrDebug = 0,
    BuiltinPe = 1,
    BuiltinWin32Runtime = 2,
    BuiltinElf = 3,
    BuiltinLinuxRuntime = 4,
};

[[nodiscard]] constexpr std::string_view to_string(StructureSchemaOrigin origin) noexcept {
    switch (origin) {
        case StructureSchemaOrigin::UserOrDebug:         return "Debug / User";
        case StructureSchemaOrigin::BuiltinPe:           return "PE Header";
        case StructureSchemaOrigin::BuiltinWin32Runtime: return "Win32 Runtime";
        case StructureSchemaOrigin::BuiltinElf:          return "ELF Header";
        case StructureSchemaOrigin::BuiltinLinuxRuntime: return "Linux Runtime";
    }
    return "Debug / User";
}

struct CatalogTypeEntry {
    DataTypeRecord record{};
    StructureSchemaOrigin origin = StructureSchemaOrigin::UserOrDebug;

    [[nodiscard]] constexpr bool is_builtin() const noexcept {
        return origin != StructureSchemaOrigin::UserOrDebug;
    }
};

/// Returns the built-in PE, Win32 runtime (PEB/TEB/RTL_USER_PROCESS_PARAMETERS),
/// ELF, and Linux dynamic-linker (`r_debug` / `link_map`) structure catalog.
[[nodiscard]] const std::vector<CatalogTypeEntry>& builtin_structure_catalog();

class StructureCatalog {
public:
    StructureCatalog() = default;

    [[nodiscard]] static StructureCatalog build(
        std::span<const DataTypeRecord> primary_user_types = {},
        std::span<const DataTypeRecord> secondary_user_types = {},
        bool include_builtins = true);

    [[nodiscard]] std::span<const CatalogTypeEntry> entries() const noexcept { return entries_; }
    [[nodiscard]] std::size_t size() const noexcept { return entries_.size(); }
    [[nodiscard]] bool empty() const noexcept { return entries_.empty(); }

    [[nodiscard]] const CatalogTypeEntry* find_entry(std::string_view type_name) const noexcept;
    [[nodiscard]] const DataTypeRecord* find(std::string_view type_name) const noexcept;

private:
    void add_entry(CatalogTypeEntry entry);

    std::vector<CatalogTypeEntry> entries_{};
    std::unordered_map<std::string, std::size_t> by_canonical_name_{};
};

/// Abstract byte reader allowing `evaluate_structure` to operate uniformly over
/// raw byte spans, static `IBinaryImage` files (by VA or file offset), live
/// read-only `IProcessSession` memory (tolerating unreadable/guard pages), and `BinaryModel`.
class IStructureByteSource {
public:
    virtual ~IStructureByteSource() = default;

    [[nodiscard]] virtual peelf::MemorySample read_bytes(
        std::uint64_t address,
        bool is_file_offset,
        std::size_t size) const = 0;

    [[nodiscard]] virtual std::optional<std::uint64_t> to_virtual_address(
        std::uint64_t address,
        bool is_file_offset) const noexcept {
        if (!is_file_offset) {
            return address;
        }
        return std::nullopt;
    }

    [[nodiscard]] virtual std::optional<std::uint64_t> to_window_offset(
        std::uint64_t address,
        bool is_file_offset) const noexcept {
        if (is_file_offset) {
            return address;
        }
        return std::nullopt;
    }

    [[nodiscard]] virtual std::string describe_pointer(std::uint64_t /*target_va*/) const {
        return {};
    }
};

class SpanStructureByteSource final : public IStructureByteSource {
public:
    SpanStructureByteSource(
        std::span<const std::uint8_t> bytes,
        std::uint64_t base_virtual_address = 0,
        std::span<const std::uint8_t> valid_mask = {},
        std::function<std::string(std::uint64_t)> pointer_annotator = {})
        : bytes_(bytes),
          valid_mask_(valid_mask),
          base_va_(base_virtual_address),
          annotator_(std::move(pointer_annotator)) {}

    [[nodiscard]] peelf::MemorySample read_bytes(
        std::uint64_t address,
        bool is_file_offset,
        std::size_t size) const override;

    [[nodiscard]] std::optional<std::uint64_t> to_virtual_address(
        std::uint64_t address,
        bool is_file_offset) const noexcept override;

    [[nodiscard]] std::optional<std::uint64_t> to_window_offset(
        std::uint64_t address,
        bool is_file_offset) const noexcept override;

    [[nodiscard]] std::string describe_pointer(std::uint64_t target_va) const override;

private:
    std::span<const std::uint8_t> bytes_{};
    std::span<const std::uint8_t> valid_mask_{};
    std::uint64_t base_va_ = 0;
    std::function<std::string(std::uint64_t)> annotator_{};
};

class StaticImageStructureByteSource final : public IStructureByteSource {
public:
    StaticImageStructureByteSource(
        const peelf::IBinaryImage& image,
        std::span<const std::uint8_t> file_bytes,
        std::function<std::string(std::uint64_t)> pointer_annotator = {})
        : image_(image),
          file_bytes_(file_bytes),
          annotator_(std::move(pointer_annotator)) {}

    [[nodiscard]] peelf::MemorySample read_bytes(
        std::uint64_t address,
        bool is_file_offset,
        std::size_t size) const override;

    [[nodiscard]] std::optional<std::uint64_t> to_virtual_address(
        std::uint64_t address,
        bool is_file_offset) const noexcept override;

    [[nodiscard]] std::optional<std::uint64_t> to_window_offset(
        std::uint64_t address,
        bool is_file_offset) const noexcept override;

    [[nodiscard]] std::string describe_pointer(std::uint64_t target_va) const override;

private:
    const peelf::IBinaryImage& image_;
    std::span<const std::uint8_t> file_bytes_{};
    std::function<std::string(std::uint64_t)> annotator_{};
};

class LiveProcessStructureByteSource final : public IStructureByteSource {
public:
    LiveProcessStructureByteSource(
        peelf::IProcessSession& session,
        std::span<const peelf::MemoryRegion> regions = {},
        std::function<std::string(std::uint64_t)> symbol_annotator = {})
        : session_(session),
          regions_(regions),
          annotator_(std::move(symbol_annotator)) {}

    [[nodiscard]] peelf::MemorySample read_bytes(
        std::uint64_t address,
        bool is_file_offset,
        std::size_t size) const override;

    [[nodiscard]] std::optional<std::uint64_t> to_virtual_address(
        std::uint64_t address,
        bool is_file_offset) const noexcept override {
        if (is_file_offset) {
            return std::nullopt;
        }
        return address;
    }

    [[nodiscard]] std::string describe_pointer(std::uint64_t target_va) const override;

private:
    peelf::IProcessSession& session_;
    std::span<const peelf::MemoryRegion> regions_{};
    std::function<std::string(std::uint64_t)> annotator_{};
};

class BinaryModelStructureByteSource final : public IStructureByteSource {
public:
    explicit BinaryModelStructureByteSource(
        const BinaryModel& model,
        std::function<std::string(std::uint64_t)> custom_annotator = {})
        : model_(model),
          custom_annotator_(std::move(custom_annotator)) {}

    [[nodiscard]] peelf::MemorySample read_bytes(
        std::uint64_t address,
        bool is_file_offset,
        std::size_t size) const override;

    [[nodiscard]] std::optional<std::uint64_t> to_virtual_address(
        std::uint64_t address,
        bool is_file_offset) const noexcept override;

    [[nodiscard]] std::optional<std::uint64_t> to_window_offset(
        std::uint64_t address,
        bool is_file_offset) const noexcept override;

    [[nodiscard]] std::string describe_pointer(std::uint64_t target_va) const override;

private:
    const BinaryModel& model_;
    std::function<std::string(std::uint64_t)> custom_annotator_{};
};

struct EvaluatedField {
    std::string name{};
    std::string type_name{};
    std::uint64_t address = 0;
    std::uint64_t relative_offset = 0;
    std::uint64_t size = 0;
    std::optional<std::uint64_t> virtual_address{};
    std::optional<std::uint64_t> window_offset{};
    std::string decoded_value{};
    std::string raw_bytes_hex{};
    peelf::Availability availability = peelf::Availability::Available;

    bool is_pointer = false;
    bool is_aggregate = false;
    std::optional<std::uint64_t> pointer_target_va{};
    std::string pointee_type_name{};
    std::string pointer_annotation{};
    std::string string_preview{};

    std::vector<EvaluatedField> children{};
};

struct StructureEvalOptions {
    peelf::TargetLayout layout{};
    std::uint32_t count = 1;
    std::size_t max_depth = 8;
    std::size_t max_array_elements = 64;
    std::size_t max_pointer_deref_depth = 2;
    bool dereference_struct_pointers = true;
};

struct EvaluatedStructure {
    std::string type_name{};
    StructureSchemaOrigin origin = StructureSchemaOrigin::UserOrDebug;
    std::uint64_t base_address = 0;
    bool is_file_offset = false;
    std::uint32_t count = 1;
    std::uint64_t stride = 0;
    std::uint64_t total_size = 0;
    peelf::TargetLayout layout{};
    peelf::Availability availability = peelf::Availability::Available;
    std::vector<EvaluatedField> fields{};
};

/// Evaluates `type_name` (1..count instances) against `source` at `address` using
/// `options.layout` (`EndianReader` + `TargetLayout`), expanding nested structs/unions,
/// fixed-size arrays, and pointer targets with depth & cycle protection.
[[nodiscard]] peelf::Result<EvaluatedStructure> evaluate_structure(
    const StructureCatalog& catalog,
    std::string_view type_name,
    std::uint64_t address,
    bool is_file_offset,
    const IStructureByteSource& source,
    const StructureEvalOptions& options);

} // namespace viewer
