//
// Created by wsoll on 12/27/2025.
//

#ifndef PEELF_EXPLORER_IMAGE_DELAY_LOAD_DESCRIPTOR_HPP
#define PEELF_EXPLORER_IMAGE_DELAY_LOAD_DESCRIPTOR_HPP

#include <cstdint>

namespace pe {

#pragma pack(push, 1)

// Delay-load directory table entry
// Used to support delay-loading of DLLs until first call
struct ImageDelayLoadDescriptor {
    // Must be zero. Reserved for future use.
    // Can indicate presence of new fields or behaviors.
    std::uint32_t Attributes{0};

    // RVA of the name of the DLL to be loaded.
    // The name resides in the read-only data section of the image.
    std::uint32_t DllNameRVA{0};

    // RVA of the module handle (in the data section).
    // Used for storage by the delay-load helper routine.
    // The helper stores the handle to the loaded DLL here.
    std::uint32_t ModuleHandleRVA{0};

    // RVA of the delay-load import address table (IAT).
    // The delay-load helper updates these pointers with real
    // entry points so thunks are no longer in the calling loop.
    std::uint32_t ImportAddressTableRVA{0};

    // RVA of the delay-load import name table (INT).
    // Contains the names of imports that might need to be loaded.
    // Matches the layout of the standard import name table.
    std::uint32_t ImportNameTableRVA{0};

    // RVA of the bound delay-load address table (BIAT), if it exists.
    // Optional table used with the timestamp field for post-process binding.
    std::uint32_t BoundImportAddressTableRVA{0};

    // RVA of the unload delay-load address table (UIAT), if it exists.
    // Exact copy of the delay IAT. If caller unloads the DLL,
    // this table should be copied back over the delay IAT
    // so subsequent calls continue to use the thunking mechanism.
    std::uint32_t UnloadInformationTableRVA{0};

    // Timestamp of the DLL to which this image has been bound.
    // Used for binding validation.
    std::uint32_t TimeDateStamp{0};
};

#pragma pack(pop)

static_assert(sizeof(ImageDelayLoadDescriptor) == 32, "ImageDelayLoadDescriptor must be 32 bytes");

// Delay-load attributes flags
namespace delay_load_attributes {
    // If set, use RVAs instead of pointers.
    // All modern delay-load descriptors use RVAs.
    inline constexpr std::uint32_t RVA_BASED = 0x00000001u;
} // namespace delay_load_attributes

// Helper to check if delay-load descriptor is valid (not the null terminator)
[[nodiscard]] constexpr bool is_valid_delay_load_descriptor(const ImageDelayLoadDescriptor& desc) noexcept {
    return desc.DllNameRVA != 0u;
}

// Helper to check if delay-load uses RVAs (modern format)
[[nodiscard]] constexpr bool is_rva_based(const ImageDelayLoadDescriptor& desc) noexcept {
    return (desc.Attributes & delay_load_attributes::RVA_BASED) != 0u;
}

// Helper to check if delay-load has bound imports
[[nodiscard]] constexpr bool has_bound_imports(const ImageDelayLoadDescriptor& desc) noexcept {
    return desc.BoundImportAddressTableRVA != 0u;
}

// Helper to check if delay-load has unload information
[[nodiscard]] constexpr bool has_unload_info(const ImageDelayLoadDescriptor& desc) noexcept {
    return desc.UnloadInformationTableRVA != 0u;
}

// Helper to check if delay-load is bound (has valid timestamp)
[[nodiscard]] constexpr bool is_bound(const ImageDelayLoadDescriptor& desc) noexcept {
    return desc.TimeDateStamp != 0u;
}

} // namespace pe
#endif //PEELF_EXPLORER_IMAGE_DELAY_LOAD_DESCRIPTOR_HPP