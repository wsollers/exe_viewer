#include "navigation/viewer_navigation.hpp"

#include <algorithm>
#include <string>

namespace viewer {
namespace {

[[nodiscard]] StructureNode group_node(std::string label) {
    return StructureNode{
        .selection = ViewerSelection{
            .kind = SelectionKind::Group,
            .label = std::move(label),
            .preferred_view = PreferredView::Details
        }
    };
}

[[nodiscard]] StructureNode selectable_node(SelectionKind kind,
                                            std::string label,
                                            std::uint64_t object_index,
                                            PreferredView preferred_view) {
    return StructureNode{
        .selection = ViewerSelection{
            .kind = kind,
            .label = std::move(label),
            .object_index = object_index,
            .preferred_view = preferred_view
        }
    };
}

[[nodiscard]] PreferredView section_view(const peelf::Section& section) {
    return section.executable ? PreferredView::Disassembly : PreferredView::Hex;
}

void add_headers(const peelf::IBinaryImage& image, StructureNode& root) {
    StructureNode headers = group_node("Headers");
    headers.children.push_back(selectable_node(SelectionKind::Header, "Image Identity", 0, PreferredView::Details));

    if (const peelf::ElfHeader* elf = image.elf_header()) {
        StructureNode node = selectable_node(SelectionKind::Header, "ELF File Header", 1, PreferredView::Details);
        node.selection.file_offset = 0;
        node.selection.virtual_address = elf->entry;
        node.selection.size = elf->header_size;
        headers.children.push_back(std::move(node));
    } else if (image.format() == peelf::Format::PE) {
        StructureNode dos = selectable_node(SelectionKind::Header, "DOS Header", 1, PreferredView::Details);
        dos.selection.file_offset = 0;
        dos.selection.size = 0x40;
        headers.children.push_back(std::move(dos));
        headers.children.push_back(selectable_node(SelectionKind::Header, "PE/COFF Headers", 2, PreferredView::Details));
    }

    root.children.push_back(std::move(headers));
}

void add_sections(const peelf::IBinaryImage& image, StructureNode& root) {
    StructureNode sections = group_node("Sections");
    std::uint64_t index = 0;
    for (const peelf::Section& section : image.sections()) {
        StructureNode node = selectable_node(SelectionKind::Section, section.name, index, section_view(section));
        node.selection.file_offset = section.file_offset;
        node.selection.virtual_address = section.virtual_address;
        node.selection.size = std::max(section.file_size, section.virtual_size);
        sections.children.push_back(std::move(node));
        ++index;
    }
    root.children.push_back(std::move(sections));
}

void add_segments(const peelf::IBinaryImage& image, StructureNode& root) {
    if (image.segments().empty()) {
        return;
    }

    StructureNode segments = group_node("Segments");
    std::uint64_t index = 0;
    for (const peelf::Segment& segment : image.segments()) {
        StructureNode node = selectable_node(SelectionKind::Segment,
                                             "Segment " + std::to_string(index),
                                             index,
                                             segment.executable ? PreferredView::Disassembly : PreferredView::Hex);
        node.selection.file_offset = segment.file_offset;
        node.selection.virtual_address = segment.virtual_address;
        node.selection.size = std::max(segment.file_size, segment.virtual_size);
        segments.children.push_back(std::move(node));
        ++index;
    }
    root.children.push_back(std::move(segments));
}

void add_imports(const peelf::IBinaryImage& image, StructureNode& root) {
    StructureNode imports = group_node("Imports");
    std::uint64_t index = 0;
    for (const peelf::ImportEntry& entry : image.imports()) {
        std::string label = entry.library;
        if (!entry.name.empty()) {
            label += "!";
            label += entry.name;
        }
        StructureNode node = selectable_node(SelectionKind::Import, std::move(label), index, PreferredView::Details);
        if (entry.address != 0) {
            node.selection.virtual_address = entry.address;
        }
        imports.children.push_back(std::move(node));
        ++index;
    }
    root.children.push_back(std::move(imports));
}

void add_exports(const peelf::IBinaryImage& image, StructureNode& root) {
    StructureNode exports = group_node("Exports");
    std::uint64_t index = 0;
    for (const peelf::ExportEntry& entry : image.exports()) {
        StructureNode node = selectable_node(SelectionKind::Export, entry.name, index, PreferredView::Disassembly);
        if (entry.virtual_address != 0) {
            node.selection.virtual_address = entry.virtual_address;
            node.selection.file_offset = image.virtual_address_to_file_offset(entry.virtual_address);
        }
        exports.children.push_back(std::move(node));
        ++index;
    }
    root.children.push_back(std::move(exports));
}

void add_symbols(const peelf::IBinaryImage& image, StructureNode& root) {
    StructureNode symbols = group_node("Symbols");
    std::uint64_t index = 0;
    for (const peelf::Symbol& symbol : image.symbols()) {
        StructureNode node = selectable_node(SelectionKind::Symbol, symbol.name, index, PreferredView::Disassembly);
        if (symbol.virtual_address != 0) {
            node.selection.virtual_address = symbol.virtual_address;
            node.selection.file_offset = image.virtual_address_to_file_offset(symbol.virtual_address);
        }
        node.selection.size = symbol.size;
        symbols.children.push_back(std::move(node));
        ++index;
    }
    root.children.push_back(std::move(symbols));
}

void add_pe_metadata(const peelf::IBinaryImage& image, StructureNode& root) {
    if (image.format() != peelf::Format::PE) {
        return;
    }

    StructureNode relocations = group_node("Base Relocations");
    std::uint64_t block_index = 0;
    for (const peelf::PeBaseRelocationBlock& block : image.pe_base_relocations()) {
        StructureNode node = selectable_node(SelectionKind::Relocation,
                                             "Block " + std::to_string(block_index),
                                             block_index,
                                             PreferredView::Details);
        node.selection.size = block.block_size;
        relocations.children.push_back(std::move(node));
        ++block_index;
    }
    root.children.push_back(std::move(relocations));

    StructureNode debug = group_node("Debug Directories");
    std::uint64_t debug_index = 0;
    for (const peelf::PeDebugDirectory& entry : image.pe_debug_directories()) {
        StructureNode node = selectable_node(SelectionKind::DebugDirectory,
                                             entry.codeview_pdb_path.empty() ? "Debug Directory" : entry.codeview_pdb_path,
                                             debug_index,
                                             PreferredView::Details);
        node.selection.file_offset = entry.pointer_to_raw_data;
        node.selection.size = entry.size_of_data;
        debug.children.push_back(std::move(node));
        ++debug_index;
    }
    root.children.push_back(std::move(debug));

    StructureNode runtime_functions = group_node("Runtime Functions");
    std::uint64_t runtime_index = 0;
    for (const peelf::PeRuntimeFunction& entry : image.pe_runtime_functions()) {
        StructureNode node = selectable_node(SelectionKind::RuntimeFunction,
                                             "Function " + std::to_string(runtime_index),
                                             runtime_index,
                                             PreferredView::Details);
        node.selection.file_offset = entry.file_offset;
        node.selection.virtual_address = image.file_offset_to_virtual_address(entry.file_offset);
        node.selection.size = 12;
        runtime_functions.children.push_back(std::move(node));
        ++runtime_index;
    }
    root.children.push_back(std::move(runtime_functions));

    if (const peelf::PeTlsDirectory* tls = image.pe_tls_directory()) {
        StructureNode tls_node = selectable_node(SelectionKind::TlsDirectory,
                                                 "TLS Directory",
                                                 0,
                                                 PreferredView::Details);
        if (tls->raw_data_start_va != 0) {
            tls_node.selection.virtual_address = tls->raw_data_start_va;
            tls_node.selection.file_offset = image.virtual_address_to_file_offset(tls->raw_data_start_va);
        }
        tls_node.selection.size = tls->raw_data_end_va > tls->raw_data_start_va
            ? tls->raw_data_end_va - tls->raw_data_start_va
            : 0;
        root.children.push_back(std::move(tls_node));
    }

    StructureNode certificates = group_node("Certificates");
    std::uint64_t certificate_index = 0;
    for (const peelf::PeCertificate& certificate : image.pe_certificates()) {
        StructureNode node = selectable_node(SelectionKind::Certificate,
                                             "Certificate " + std::to_string(certificate_index),
                                             certificate_index,
                                             PreferredView::Hex);
        node.selection.file_offset = certificate.file_offset;
        node.selection.size = certificate.length;
        certificates.children.push_back(std::move(node));
        ++certificate_index;
    }
    root.children.push_back(std::move(certificates));

    if (const peelf::PeLoadConfigDirectory* load_config = image.pe_load_config_directory()) {
        StructureNode node = selectable_node(SelectionKind::LoadConfig,
                                             "Load Config",
                                             0,
                                             PreferredView::Details);
        node.selection.file_offset = load_config->file_offset;
        node.selection.virtual_address = image.file_offset_to_virtual_address(load_config->file_offset);
        node.selection.size = load_config->size;
        root.children.push_back(std::move(node));
    }
}

void add_elf_metadata(const peelf::IBinaryImage& image, StructureNode& root) {
    if (image.format() != peelf::Format::ELF) {
        return;
    }

    if (!image.elf_interpreter().empty()) {
        StructureNode interpreter = selectable_node(SelectionKind::Interpreter,
                                                   std::string(image.elf_interpreter()),
                                                   0,
                                                   PreferredView::Details);
        root.children.push_back(std::move(interpreter));
    }

    StructureNode dynamic = group_node("Dynamic Entries");
    std::uint64_t dynamic_index = 0;
    for (const peelf::ElfDynamicEntry& entry : image.elf_dynamic_entries()) {
        std::string label = entry.needed_library.empty()
            ? "Tag " + std::to_string(entry.tag)
            : "Needed " + entry.needed_library;
        StructureNode node = selectable_node(SelectionKind::DynamicEntry, std::move(label), dynamic_index, PreferredView::Details);
        node.selection.virtual_address = entry.value;
        dynamic.children.push_back(std::move(node));
        ++dynamic_index;
    }
    root.children.push_back(std::move(dynamic));

    StructureNode relocations = group_node("Relocations");
    std::uint64_t relocation_index = 0;
    for (const peelf::ElfRelocation& relocation : image.elf_relocations()) {
        StructureNode node = selectable_node(SelectionKind::Relocation,
                                             relocation.section_name,
                                             relocation_index,
                                             PreferredView::Details);
        node.selection.virtual_address = relocation.offset;
        relocations.children.push_back(std::move(node));
        ++relocation_index;
    }
    root.children.push_back(std::move(relocations));

    StructureNode notes = group_node("Notes");
    std::uint64_t note_index = 0;
    for (const peelf::ElfNote& note : image.elf_notes()) {
        StructureNode node = selectable_node(SelectionKind::Note, note.name, note_index, PreferredView::Details);
        node.selection.size = note.descriptor.size();
        notes.children.push_back(std::move(node));
        ++note_index;
    }
    root.children.push_back(std::move(notes));

    StructureNode hashes = group_node("Hash Tables");
    std::uint64_t hash_index = 0;
    for (const peelf::ElfSysvHashTable& table : image.elf_sysv_hash_tables()) {
        hashes.children.push_back(selectable_node(SelectionKind::HashTable, table.section_name, hash_index, PreferredView::Details));
        ++hash_index;
    }
    for (const peelf::ElfGnuHashTable& table : image.elf_gnu_hash_tables()) {
        hashes.children.push_back(selectable_node(SelectionKind::HashTable, table.section_name, hash_index, PreferredView::Details));
        ++hash_index;
    }
    root.children.push_back(std::move(hashes));
}

} // namespace

StructureNode build_structure_tree(const peelf::IBinaryImage& image) {
    StructureNode root{
        .selection = ViewerSelection{
            .kind = SelectionKind::Image,
            .label = std::string(peelf::to_string(image.format())) + " Image",
            .virtual_address = image.entry_point(),
            .preferred_view = PreferredView::Details
        }
    };

    add_headers(image, root);
    add_sections(image, root);
    add_segments(image, root);
    add_imports(image, root);
    add_exports(image, root);
    add_symbols(image, root);
    add_pe_metadata(image, root);
    add_elf_metadata(image, root);

    return root;
}

} // namespace viewer
