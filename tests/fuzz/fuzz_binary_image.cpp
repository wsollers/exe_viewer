#include "fuzz_targets.hpp"

#include <peelf/binary_image.hpp>
#include <peelf/clr_metadata.hpp>
#include <peelf/executable_settings.hpp>
#include <peelf/security_audit.hpp>
#include <peelf/signatures.hpp>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <span>

namespace peelf::fuzz {

namespace {

void exercise_binary_image(const IBinaryImage& img,
                           std::span<const std::uint8_t> raw_bytes) noexcept {
    std::uint64_t acc = static_cast<std::uint64_t>(img.format());
    acc ^= static_cast<std::uint64_t>(img.kind()) << 4u;
    acc ^= static_cast<std::uint64_t>(img.architecture()) << 8u;
    acc ^= static_cast<std::uint64_t>(img.endianness()) << 16u;
    acc ^= img.is_64bit() ? 0x64u : 0x32u;
    acc ^= img.image_base();
    acc ^= img.entry_point();
    acc ^= img.parse_warnings().size();

    if (img.is_universal_slice()) {
        acc ^= img.container_slice_index();
        acc ^= img.container_slice_offset();
        acc ^= img.container_slice_size();
        (void)img.slice_relative_offset(img.container_slice_offset());
        (void)img.container_file_offset(0u);
    }

    const auto& sections = img.sections();
    const std::size_t max_sections = std::min<std::size_t>(sections.size(), 32u);
    for (std::size_t i = 0u; i < max_sections; ++i) {
        const auto& sec = sections[i];
        acc ^= sec.name.size() ^ sec.virtual_address ^ sec.file_offset;
        if (const auto off = img.va_to_file_offset(sec.virtual_address)) {
            acc ^= *off;
        }
        if (const auto va = img.file_offset_to_va(sec.file_offset)) {
            acc ^= *va;
        }
        if (const auto rd = img.read_bytes_at_va(sec.virtual_address, 16u); rd.has_value()) {
            acc ^= rd->size();
        }
        if (const auto rd = img.read_bytes_at_offset(sec.file_offset, 16u); rd.has_value()) {
            acc ^= rd->size();
        }
    }

    const auto& segments = img.segments();
    const std::size_t max_segments = std::min<std::size_t>(segments.size(), 32u);
    for (std::size_t i = 0u; i < max_segments; ++i) {
        const auto& seg = segments[i];
        acc ^= seg.virtual_address ^ seg.file_offset ^ seg.virtual_size;
        (void)img.va_to_file_offset(seg.virtual_address);
        (void)img.file_offset_to_va(seg.file_offset);
    }

    const auto& syms = img.symbols();
    acc ^= syms.size();
    if (!syms.empty()) {
        acc ^= syms.front().name.size() ^ syms.front().virtual_address;
        acc ^= syms.back().name.size() ^ syms.back().virtual_address;
    }

    const auto& imps = img.imports();
    acc ^= imps.size();
    if (!imps.empty()) {
        acc ^= imps.front().library.size() ^ imps.front().name.size() ^ imps.front().address;
    }

    const auto& exps = img.exports();
    acc ^= exps.size();
    if (!exps.empty()) {
        acc ^= exps.front().name.size() ^ exps.front().virtual_address;
    }

    constexpr std::array<std::uint64_t, 5> kBoundaryProbes = {
        0u,
        4096u,
        0xFFFFFFFFull,
        std::numeric_limits<std::uint64_t>::max() - 15u,
        std::numeric_limits<std::uint64_t>::max(),
    };
    for (const std::uint64_t probe : kBoundaryProbes) {
        (void)img.va_to_file_offset(probe);
        (void)img.file_offset_to_va(probe);
        (void)img.read_bytes_at_va(probe, 16u);
        (void)img.read_bytes_at_offset(probe, 16u);
    }
    (void)img.va_to_file_offset(img.entry_point());
    (void)img.read_bytes_at_va(img.entry_point(), 32u);

    // Format-specific metadata accessors.
    acc ^= (img.pe_header() != nullptr) ? 1u : 0u;
    acc ^= img.pe_data_directories().size();
    acc ^= img.pe_base_relocations().size();
    acc ^= img.pe_debug_directories().size();
    acc ^= img.pe_certificates().size();
    acc ^= img.pe_runtime_functions().size();
    acc ^= img.pe_bound_imports().size();
    acc ^= img.pe_resource_data_entries().size();
    acc ^= (img.elf_header() != nullptr) ? 2u : 0u;
    acc ^= img.elf_program_headers().size();
    acc ^= img.elf_section_headers().size();
    acc ^= img.elf_dynamic_entries().size();
    acc ^= img.elf_relocations().size();
    acc ^= img.elf_notes().size();
    acc ^= img.elf_interpreter().size();
    acc ^= (img.macho_header() != nullptr) ? 4u : 0u;
    acc ^= img.macho_load_commands().size();
    acc ^= img.macho_segments().size();
    acc ^= img.macho_sections().size();
    acc ^= img.macho_dylibs().size();
    acc ^= img.macho_rpaths().size();
    acc ^= img.macho_build_versions().size();

    if (img.pe_clr_header() != nullptr) {
        if (const auto clr_md = parse_clr_metadata(img, raw_bytes); clr_md.has_value()) {
            acc ^= clr_md->type_defs.size() ^ clr_md->methods.size() ^
                   clr_md->assembly_refs.size() ^ clr_md->pinvoke_entries.size() ^
                   clr_md->user_strings.size();
            std::size_t decoded_methods = 0u;
            for (const ClrMethodDef& m : clr_md->methods) {
                if (m.rva == 0u) {
                    continue;
                }
                if (const auto body = disassemble_cil_method(img, raw_bytes, *clr_md, m);
                    body.has_value()) {
                    acc ^= body->instructions.size() ^ body->eh_clauses.size() ^ body->code_size;
                }
                if (++decoded_methods >= 16u) {
                    break;
                }
            }
        }
    }

    const auto audit = audit_security(img, raw_bytes);
    acc ^= audit.findings.size() ^ audit.pass_count ^ audit.warning_count ^ audit.error_count;

    const auto settings = extract_executable_settings(img, raw_bytes);
    acc ^= settings.schema_version;
    if (settings.declared_in_file.value.has_value()) {
        acc ^= settings.declared_in_file.value->declared_dependencies.size();
    }

    const auto crypto_hits = scan_crypto_and_packer_constants(raw_bytes, &img);
    acc ^= crypto_hits.size();

    sink_u64(acc);
}

} // namespace

void fuzz_binary_image_one_input(std::span<const std::uint8_t> data) noexcept {
    if (data.size() > kMaxFuzzInputBytes) {
        return;
    }

    const Format fmt = detect_format(data);
    sink_u64(static_cast<std::uint64_t>(fmt));

    if (const auto rich = parse_pe_rich_header(data)) {
        sink_u64(rich->entries.size() ^ rich->diagnostic.size() ^ (rich->checksum_valid ? 1u : 0u));
    }

    const auto container = inspect_binary_container(data);
    const auto primary = parse_image(data);
    if (primary.has_value() && *primary != nullptr) {
        exercise_binary_image(**primary, data);
    } else {
        // Still exercise raw packer/crypto constant scanner on bounded unparsed buffers.
        const auto raw_window = data.first(std::min<std::size_t>(data.size(), 16u * 1024u));
        const auto hits = scan_crypto_and_packer_constants(raw_window, nullptr);
        sink_u64(hits.size());
    }

    if (container.has_value() && container->slices.size() > 1u) {
        const std::size_t max_slices = std::min<std::size_t>(container->slices.size(), 4u);
        for (std::size_t idx = 0u; idx < max_slices; ++idx) {
            BinaryOpenOptions opts{};
            opts.selected_slice_index = idx;
            if (const auto slice_img = parse_image(data, opts);
                slice_img.has_value() && *slice_img != nullptr) {
                exercise_binary_image(**slice_img, data);
            }
        }
    }
}

} // namespace peelf::fuzz

#ifdef PEELF_LIBFUZZER_HARNESS
// NOLINTNEXTLINE(readability-identifier-naming)
extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    if (size > peelf::fuzz::kMaxFuzzInputBytes) {
        return 0;
    }
    const std::span<const std::uint8_t> bytes = (data != nullptr)
                                                    ? std::span<const std::uint8_t>(data, size)
                                                    : std::span<const std::uint8_t>{};
    peelf::fuzz::fuzz_binary_image_one_input(bytes);
    return 0;
}
#endif
