//
// Created by wsoll on 12/27/2025.
//

#ifndef PEELF_EXPLORER_IMAGE_DELAY_LOAD_DESCRIPTOR_HPP
#define PEELF_EXPLORER_IMAGE_DELAY_LOAD_DESCRIPTOR_HPP
namespace pe {

#pragma pack(push, 1)

// Delay-load directory table entry
// Used to support delay-loading of DLLs until first call
struct ImageDelayLoadDescriptor {
    // Must be zero. Reserved for future use.
    // Can indicate presence of new fields or behaviors.
    uint32_t Attributes;

    // RVA of the name of the DLL to be loaded.
    // The name resides in the read-only data section of the image.
    uint32_t DllNameRVA;

    // RVA of the module handle (in the data section).
    // Used for storage by the delay-load helper routine.
    // The helper stores the handle to the loaded DLL here.
    uint32_t ModuleHandleRVA;

    // RVA of the delay-load import address table (IAT).
    // The delay-load helper updates these pointers with real
    // entry points so thunks are no longer in the calling loop.
    uint32_t ImportAddressTableRVA;

    // RVA of the delay-load import name table (INT).
    // Contains the names of imports that might need to be loaded.
    // Matches the layout of the standard import name table.
    uint32_t ImportNameTableRVA;

    // RVA of the bound delay-load address table (BIAT), if it exists.
    // Optional table used with the timestamp field for post-process binding.
    uint32_t BoundImportAddressTableRVA;

    // RVA of the unload delay-load address table (UIAT), if it exists.
    // Exact copy of the delay IAT. If caller unloads the DLL,
    // this table should be copied back over the delay IAT
    // so subsequent calls continue to use the thunking mechanism.
    uint32_t UnloadInformationTableRVA;

    // Timestamp of the DLL to which this image has been bound.
    // Used for binding validation.
    uint32_t TimeDateStamp;
};

#pragma pack(pop)

static_assert(sizeof(ImageDelayLoadDescriptor) == 32, "ImageDelayLoadDescriptor must be 32 bytes");

// Delay-load attributes flags
namespace delay_load_attributes {
    // If set, use RVAs instead of pointers.
    // All modern delay-load descriptors use RVAs.
    constexpr uint32_t RVA_BASED = 0x00000001;
}

// Helper to check if delay-load descriptor is valid (not the null terminator)
constexpr bool is_valid_delay_load_descriptor(const ImageDelayLoadDescriptor& desc) {
    return desc.DllNameRVA != 0;
}

// Helper to check if delay-load uses RVAs (modern format)
constexpr bool is_rva_based(const ImageDelayLoadDescriptor& desc) {
    return desc.Attributes & delay_load_attributes::RVA_BASED;
}

// Helper to check if delay-load has bound imports
constexpr bool has_bound_imports(const ImageDelayLoadDescriptor& desc) {
    return desc.BoundImportAddressTableRVA != 0;
}

// Helper to check if delay-load has unload information
constexpr bool has_unload_info(const ImageDelayLoadDescriptor& desc) {
    return desc.UnloadInformationTableRVA != 0;
}

// Helper to check if delay-load is bound (has valid timestamp)
constexpr bool is_bound(const ImageDelayLoadDescriptor& desc) {
    return desc.TimeDateStamp != 0;
}

} // namespace pe
#endif //PEELF_EXPLORER_IMAGE_DELAY_LOAD_DESCRIPTOR_HPP