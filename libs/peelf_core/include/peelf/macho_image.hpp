#pragma once

#include <peelf/binary_image.hpp>
#include <peelf/error.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace peelf {

namespace macho {

// Thin Mach-O magic values (in target-native vs byte-swapped 32-bit representation).
inline constexpr std::uint32_t kMhMagic   = 0xFEEDFACEu;
inline constexpr std::uint32_t kMhCigam   = 0xCEFAEDFEu;
inline constexpr std::uint32_t kMhMagic64 = 0xFEEDFACFu;
inline constexpr std::uint32_t kMhCigam64 = 0xCFFAEDFEu;

// Universal / FAT container magic values (canonical big-endian wire values).
inline constexpr std::uint32_t kFatMagic   = 0xCAFEBABEu;
inline constexpr std::uint32_t kFatCigam   = 0xBEBAFECAu;
inline constexpr std::uint32_t kFatMagic64 = 0xCAFEBABFu;
inline constexpr std::uint32_t kFatCigam64 = 0xBFBAFECAu;

inline constexpr std::uint32_t kMaxFatArchCount = 32u;
inline constexpr std::uint32_t kMaxFatAlignLog2 = 30u;

// CPU architecture masks, types, and subtypes.
inline constexpr std::uint32_t kCpuArchAbi64    = 0x01000000u;
inline constexpr std::uint32_t kCpuArchAbi64_32 = 0x02000000u;
inline constexpr std::uint32_t kCpuSubtypeMask  = 0xFF000000u;

inline constexpr std::uint32_t kCpuTypeX86       = 7u;
inline constexpr std::uint32_t kCpuTypeX86_64    = 7u | kCpuArchAbi64;
inline constexpr std::uint32_t kCpuTypeArm       = 12u;
inline constexpr std::uint32_t kCpuTypeArm64     = 12u | kCpuArchAbi64;
inline constexpr std::uint32_t kCpuTypeArm64_32  = 12u | kCpuArchAbi64_32;
inline constexpr std::uint32_t kCpuTypePowerPC   = 18u;
inline constexpr std::uint32_t kCpuTypePowerPC64 = 18u | kCpuArchAbi64;
inline constexpr std::uint32_t kCpuTypeRiscV     = 24u;
inline constexpr std::uint32_t kCpuTypeRiscV64   = 24u | kCpuArchAbi64;

inline constexpr std::uint32_t kCpuSubtypeX86_64All   = 3u;
inline constexpr std::uint32_t kCpuSubtypeX86_64H     = 8u;
inline constexpr std::uint32_t kCpuSubtypeArm64All    = 0u;
inline constexpr std::uint32_t kCpuSubtypeArm64V8     = 1u;
inline constexpr std::uint32_t kCpuSubtypeArm64e      = 2u;
inline constexpr std::uint32_t kCpuSubtypePtrAuthAbi  = 0x80000000u;

// Mach-O file types.
inline constexpr std::uint32_t kMhObject      = 0x1u;
inline constexpr std::uint32_t kMhExecute     = 0x2u;
inline constexpr std::uint32_t kMhFvmlib      = 0x3u;
inline constexpr std::uint32_t kMhCore        = 0x4u;
inline constexpr std::uint32_t kMhPreload     = 0x5u;
inline constexpr std::uint32_t kMhDylib       = 0x6u;
inline constexpr std::uint32_t kMhDylinker    = 0x7u;
inline constexpr std::uint32_t kMhBundle      = 0x8u;
inline constexpr std::uint32_t kMhDylibStub   = 0x9u;
inline constexpr std::uint32_t kMhDsym        = 0xAu;
inline constexpr std::uint32_t kMhKextBundle  = 0xBu;
inline constexpr std::uint32_t kMhFileset     = 0xCu;

// Mach-O header flags.
inline constexpr std::uint32_t kMhNoUndefs               = 0x00000001u;
inline constexpr std::uint32_t kMhDyldLink               = 0x00000004u;
inline constexpr std::uint32_t kMhTwoLevel               = 0x00000080u;
inline constexpr std::uint32_t kMhForceFlat              = 0x00000100u;
inline constexpr std::uint32_t kMhWeakDefines            = 0x00008000u;
inline constexpr std::uint32_t kMhBindsToWeak            = 0x00010000u;
inline constexpr std::uint32_t kMhAllowStackExecution    = 0x00020000u;
inline constexpr std::uint32_t kMhRootSafe               = 0x00040000u;
inline constexpr std::uint32_t kMhSetuidSafe             = 0x00080000u;
inline constexpr std::uint32_t kMhPie                    = 0x00200000u;
inline constexpr std::uint32_t kMhHasTlvDescriptors      = 0x00800000u;
inline constexpr std::uint32_t kMhNoHeapExecution        = 0x01000000u;
inline constexpr std::uint32_t kMhAppExtensionSafe       = 0x02000000u;

// Load command tags.
inline constexpr std::uint32_t kLcReqDyld           = 0x80000000u;
inline constexpr std::uint32_t kLcSegment           = 0x00000001u;
inline constexpr std::uint32_t kLcSymtab            = 0x00000002u;
inline constexpr std::uint32_t kLcUnixThread        = 0x00000005u;
inline constexpr std::uint32_t kLcDysymtab          = 0x0000000Bu;
inline constexpr std::uint32_t kLcLoadDylib         = 0x0000000Cu;
inline constexpr std::uint32_t kLcIdDylib           = 0x0000000Du;
inline constexpr std::uint32_t kLcLoadDylinker      = 0x0000000Eu;
inline constexpr std::uint32_t kLcIdDylinker        = 0x0000000Fu;
inline constexpr std::uint32_t kLcLoadWeakDylib     = 0x00000018u | kLcReqDyld;
inline constexpr std::uint32_t kLcSegment64         = 0x00000019u;
inline constexpr std::uint32_t kLcUuid              = 0x0000001Bu;
inline constexpr std::uint32_t kLcRpath             = 0x0000001Cu | kLcReqDyld;
inline constexpr std::uint32_t kLcCodeSignature     = 0x0000001Du;
inline constexpr std::uint32_t kLcReexportDylib     = 0x0000001Fu | kLcReqDyld;
inline constexpr std::uint32_t kLcLazyLoadDylib     = 0x00000020u;
inline constexpr std::uint32_t kLcEncryptionInfo    = 0x00000021u;
inline constexpr std::uint32_t kLcDyldInfo          = 0x00000022u;
inline constexpr std::uint32_t kLcDyldInfoOnly      = 0x00000022u | kLcReqDyld;
inline constexpr std::uint32_t kLcLoadUpwardDylib   = 0x00000023u | kLcReqDyld;
inline constexpr std::uint32_t kLcVersionMinMacosx  = 0x00000024u;
inline constexpr std::uint32_t kLcVersionMinIphoneos = 0x00000025u;
inline constexpr std::uint32_t kLcFunctionStarts    = 0x00000026u;
inline constexpr std::uint32_t kLcMain              = 0x00000028u | kLcReqDyld;
inline constexpr std::uint32_t kLcDataInCode        = 0x00000029u;
inline constexpr std::uint32_t kLcSourceVersion     = 0x0000002Au;
inline constexpr std::uint32_t kLcEncryptionInfo64  = 0x0000002Cu;
inline constexpr std::uint32_t kLcVersionMinTvos    = 0x0000002Fu;
inline constexpr std::uint32_t kLcVersionMinWatchos = 0x00000030u;
inline constexpr std::uint32_t kLcBuildVersion      = 0x00000032u;
inline constexpr std::uint32_t kLcDyldExportsTrie   = 0x00000033u | kLcReqDyld;
inline constexpr std::uint32_t kLcDyldChainedFixups = 0x00000034u | kLcReqDyld;

// VM protection flags.
inline constexpr std::uint32_t kVmProtNone    = 0x00u;
inline constexpr std::uint32_t kVmProtRead    = 0x01u;
inline constexpr std::uint32_t kVmProtWrite   = 0x02u;
inline constexpr std::uint32_t kVmProtExecute = 0x04u;

// Section types and attributes.
inline constexpr std::uint8_t  kSectionTypeMask          = 0xFFu;
inline constexpr std::uint8_t  kSRegular                 = 0x00u;
inline constexpr std::uint8_t  kSZeroFill                = 0x01u;
inline constexpr std::uint8_t  kSNonLazySymbolPointers   = 0x06u;
inline constexpr std::uint8_t  kSLazySymbolPointers      = 0x07u;
inline constexpr std::uint8_t  kSSymbolStubs             = 0x08u;
inline constexpr std::uint8_t  kSGbZeroFill              = 0x0Cu;
inline constexpr std::uint8_t  kSThreadLocalZeroFill     = 0x12u;
inline constexpr std::uint32_t kSAttrPureInstructions    = 0x80000000u;
inline constexpr std::uint32_t kSAttrSomeInstructions    = 0x00000400u;

// nlist symbol masks and flags.
inline constexpr std::uint8_t  kNStab    = 0xE0u;
inline constexpr std::uint8_t  kNPext    = 0x10u;
inline constexpr std::uint8_t  kNType    = 0x0Eu;
inline constexpr std::uint8_t  kNExt     = 0x01u;
inline constexpr std::uint8_t  kNUndf    = 0x00u;
inline constexpr std::uint8_t  kNAbs     = 0x02u;
inline constexpr std::uint8_t  kNIndr    = 0x0Au;
inline constexpr std::uint8_t  kNPbud    = 0x0Cu;
inline constexpr std::uint8_t  kNSect    = 0x0Eu;
inline constexpr std::uint16_t kNArmThumbDef = 0x0008u;
inline constexpr std::uint16_t kNWeakRef     = 0x0040u;
inline constexpr std::uint16_t kNWeakDef     = 0x0080u;

// Build platforms.
inline constexpr std::uint32_t kPlatformMacOS        = 1u;
inline constexpr std::uint32_t kPlatformIOS          = 2u;
inline constexpr std::uint32_t kPlatformTvOS         = 3u;
inline constexpr std::uint32_t kPlatformWatchOS      = 4u;
inline constexpr std::uint32_t kPlatformBridgeOS     = 5u;
inline constexpr std::uint32_t kPlatformMacCatalyst  = 6u;
inline constexpr std::uint32_t kPlatformIOSSimulator = 7u;
inline constexpr std::uint32_t kPlatformVisionOS     = 11u;

// Embedded code signature SuperBlob / CodeDirectory constants (big-endian wire format).
inline constexpr std::uint32_t kCsMagicRequirements          = 0xFADE0C01u;
inline constexpr std::uint32_t kCsMagicCodeDirectory         = 0xFADE0C02u;
inline constexpr std::uint32_t kCsMagicEmbeddedSignature     = 0xFADE0CC0u;
inline constexpr std::uint32_t kCsMagicBlobWrapper           = 0xFADE0B01u;
inline constexpr std::uint32_t kCsMagicEmbeddedEntitlements  = 0xFADE7171u;
inline constexpr std::uint32_t kCsMagicEmbeddedDerEntitlements = 0xFADE7172u;

inline constexpr std::uint32_t kCsSlotCodeDirectory   = 0u;
inline constexpr std::uint32_t kCsSlotRequirements    = 2u;
inline constexpr std::uint32_t kCsSlotEntitlements    = 5u;
inline constexpr std::uint32_t kCsSlotDerEntitlements = 7u;
inline constexpr std::uint32_t kCsSlotSignatureSlot   = 0x10000u;

inline constexpr std::uint32_t kCsAdhoc        = 0x00000002u;
inline constexpr std::uint32_t kCsHard         = 0x00000100u;
inline constexpr std::uint32_t kCsKill         = 0x00000200u;
inline constexpr std::uint32_t kCsRestrict     = 0x00000800u;
inline constexpr std::uint32_t kCsEnforcement  = 0x00001000u;
inline constexpr std::uint32_t kCsRequireLv    = 0x00002000u;
inline constexpr std::uint32_t kCsRuntime      = 0x00010000u;
inline constexpr std::uint32_t kCsLinkerSigned = 0x00020000u;

// Fast, zero-allocation magic and Universal container disambiguation probes.
[[nodiscard]] bool has_macho_or_fat_magic_prefix(std::span<const std::uint8_t> bytes) noexcept;
[[nodiscard]] bool is_valid_macho_or_universal(std::span<const std::uint8_t> bytes) noexcept;

[[nodiscard]] std::string format_packed_version(std::uint32_t packed);
[[nodiscard]] std::string_view platform_to_string(std::uint32_t platform) noexcept;

} // namespace macho

// Clean-room cross-endian 32/64-bit Mach-O and Universal slice parser.
class MachOImage final : public IBinaryImage {
public:
    [[nodiscard]] static Result<BinaryContainerInfo> inspect_container(
        std::span<const std::uint8_t> bytes);

    [[nodiscard]] static Result<std::unique_ptr<MachOImage>> parse(
        std::span<const std::uint8_t> bytes,
        const BinaryOpenOptions& options = {});

    [[nodiscard]] Format        format()       const noexcept override { return Format::MachO; }
    [[nodiscard]] ImageKind     kind()         const noexcept override { return kind_; }
    [[nodiscard]] Architecture  architecture() const noexcept override { return arch_; }
    [[nodiscard]] Endianness    endianness()   const noexcept override { return endian_; }
    [[nodiscard]] bool          is_64bit()     const noexcept override { return is_64_; }
    [[nodiscard]] std::uint64_t image_base()   const noexcept override { return image_base_; }
    [[nodiscard]] std::uint64_t entry_point()  const noexcept override { return entry_; }

    [[nodiscard]] const std::vector<Section>& sections() const noexcept override { return sections_; }
    [[nodiscard]] const std::vector<Segment>& segments() const noexcept override { return segments_; }
    [[nodiscard]] const std::vector<Symbol>& symbols() const noexcept override { return symbols_; }
    [[nodiscard]] const std::vector<ImportEntry>& imports() const noexcept override { return imports_; }
    [[nodiscard]] const std::vector<ExportEntry>& exports() const noexcept override { return exports_; }

    [[nodiscard]] bool          is_universal_slice()     const noexcept override { return is_universal_slice_; }
    [[nodiscard]] std::size_t   container_slice_index()  const noexcept override { return slice_index_; }
    [[nodiscard]] std::uint64_t container_slice_offset() const noexcept override { return slice_offset_; }
    [[nodiscard]] std::uint64_t container_slice_size()   const noexcept override { return slice_size_; }

    [[nodiscard]] const MachOHeader* macho_header() const noexcept override { return &header_; }
    [[nodiscard]] const std::vector<MachOLoadCommandInfo>& macho_load_commands() const noexcept override {
        return load_commands_;
    }
    [[nodiscard]] const std::vector<MachOSegmentCommand>& macho_segments() const noexcept override {
        return macho_segments_;
    }
    [[nodiscard]] const std::vector<MachOSection>& macho_sections() const noexcept override {
        return macho_sections_;
    }
    [[nodiscard]] const std::vector<MachOSymbol>& macho_symbols() const noexcept override {
        return macho_symbols_;
    }
    [[nodiscard]] const MachOSymtabInfo* macho_symtab() const noexcept override {
        return symtab_.present ? &symtab_ : nullptr;
    }
    [[nodiscard]] const MachODysymtabInfo* macho_dysymtab() const noexcept override {
        return dysymtab_.present ? &dysymtab_ : nullptr;
    }
    [[nodiscard]] const std::vector<MachODylibDependency>& macho_dylibs() const noexcept override {
        return dylibs_;
    }
    [[nodiscard]] const MachODylibDependency* macho_id_dylib() const noexcept override {
        return id_dylib_ ? &*id_dylib_ : nullptr;
    }
    [[nodiscard]] const std::vector<MachORpathEntry>& macho_rpaths() const noexcept override {
        return rpaths_;
    }
    [[nodiscard]] std::string_view macho_dylinker() const noexcept override {
        return dylinker_;
    }
    [[nodiscard]] std::optional<std::array<std::uint8_t, 16>> macho_uuid() const noexcept override {
        return uuid_;
    }
    [[nodiscard]] std::string_view macho_uuid_string() const noexcept override {
        return uuid_string_;
    }
    [[nodiscard]] std::optional<std::uint64_t> macho_source_version() const noexcept override {
        return source_version_;
    }
    [[nodiscard]] const std::vector<MachOBuildVersion>& macho_build_versions() const noexcept override {
        return build_versions_;
    }
    [[nodiscard]] const MachOEncryptionInfo* macho_encryption_info() const noexcept override {
        return encryption_info_ ? &*encryption_info_ : nullptr;
    }
    [[nodiscard]] const MachODyldInfoRanges* macho_dyld_info() const noexcept override {
        return has_any_dyld_metadata_ ? &dyld_info_ : nullptr;
    }
    [[nodiscard]] const MachOCodeSignatureInfo* macho_code_signature() const noexcept override {
        return code_signature_.present ? &code_signature_ : nullptr;
    }

    [[nodiscard]] std::span<const std::string> parse_warnings() const noexcept override {
        return parse_warnings_;
    }

    [[nodiscard]] std::optional<std::uint64_t> file_offset_to_virtual_address(
        std::uint64_t file_offset) const noexcept override;
    [[nodiscard]] std::optional<std::uint64_t> virtual_address_to_file_offset(
        std::uint64_t virtual_address) const noexcept override;
    [[nodiscard]] Result<std::vector<std::uint8_t>> read_bytes_at_offset(
        std::uint64_t file_offset,
        std::size_t size) const override;
    [[nodiscard]] Result<std::vector<std::uint8_t>> read_bytes_at_va(
        std::uint64_t virtual_address,
        std::size_t size) const override;

    // Mach-O convenience queries for security audit & overview consumers.
    [[nodiscard]] bool has_pagezero() const noexcept { return has_pagezero_; }
    [[nodiscard]] std::uint64_t pagezero_size() const noexcept { return pagezero_size_; }
    [[nodiscard]] bool has_restrict_segment_or_section() const noexcept {
        return has_restrict_segment_or_section_;
    }
    [[nodiscard]] bool is_arm64e() const noexcept { return header_.is_arm64e; }
    [[nodiscard]] bool entry_uses_lc_main() const noexcept { return has_lc_main_; }
    [[nodiscard]] bool entry_uses_unixthread() const noexcept { return has_unixthread_entry_; }
    [[nodiscard]] std::uint64_t normalize_virtual_address(std::uint64_t va) const noexcept;

    void rebase_to_live_base(std::uint64_t live_base) noexcept;

private:
    MachOImage() = default;

    [[nodiscard]] static Result<std::unique_ptr<MachOImage>> parse_thin_slice(
        std::span<const std::uint8_t> slice_bytes,
        std::uint64_t container_offset,
        std::size_t slice_index,
        bool is_universal);

    void add_warning(std::string warning);

    ImageKind    kind_        = ImageKind::Unknown;
    Architecture arch_        = Architecture::Unknown;
    Endianness   endian_      = Endianness::Little;
    bool         is_64_       = false;
    std::uint64_t image_base_ = 0;
    std::uint64_t entry_      = 0;

    bool          is_universal_slice_ = false;
    std::size_t   slice_index_        = 0;
    std::uint64_t slice_offset_       = 0;
    std::uint64_t slice_size_         = 0;
    std::vector<std::uint8_t> slice_bytes_{};

    MachOHeader header_{};
    std::vector<MachOLoadCommandInfo> load_commands_{};
    std::vector<MachOSegmentCommand> macho_segments_{};
    std::vector<MachOSection> macho_sections_{};
    std::vector<MachOSymbol> macho_symbols_{};
    MachOSymtabInfo symtab_{};
    MachODysymtabInfo dysymtab_{};
    std::vector<MachODylibDependency> dylibs_{};
    std::optional<MachODylibDependency> id_dylib_{};
    std::vector<MachORpathEntry> rpaths_{};
    std::string dylinker_{};
    std::optional<std::array<std::uint8_t, 16>> uuid_{};
    std::string uuid_string_{};
    std::optional<std::uint64_t> source_version_{};
    std::vector<MachOBuildVersion> build_versions_{};
    std::optional<MachOEncryptionInfo> encryption_info_{};
    MachODyldInfoRanges dyld_info_{};
    bool has_any_dyld_metadata_ = false;
    MachOCodeSignatureInfo code_signature_{};

    bool has_pagezero_ = false;
    std::uint64_t pagezero_size_ = 0;
    bool has_restrict_segment_or_section_ = false;
    bool has_lc_main_ = false;
    std::uint64_t lc_main_entryoff_ = 0;
    bool has_unixthread_entry_ = false;

    std::vector<Section> sections_{};
    std::vector<Segment> segments_{};
    std::vector<Symbol> symbols_{};
    std::vector<ImportEntry> imports_{};
    std::vector<ExportEntry> exports_{};
    std::vector<std::string> parse_warnings_{};
};

} // namespace peelf
