#include "navigation/viewer_navigation.hpp"

#include <algorithm>
#include <cctype>
#include <charconv>
#include <format>
#include <string>

#include "graph/call_graph.hpp"

namespace viewer {
namespace {

[[nodiscard]] std::string_view trim_query_whitespace(std::string_view sv) noexcept {
    while (!sv.empty() && std::isspace(static_cast<unsigned char>(sv.front())) != 0) {
        sv.remove_prefix(1u);
    }
    while (!sv.empty() && std::isspace(static_cast<unsigned char>(sv.back())) != 0) {
        sv.remove_suffix(1u);
    }
    return sv;
}

[[nodiscard]] bool icontains_ascii(std::string_view haystack, std::string_view needle) noexcept {
    if (needle.empty()) {
        return true;
    }
    if (haystack.size() < needle.size()) {
        return false;
    }
    const auto it = std::search(
        haystack.begin(),
        haystack.end(),
        needle.begin(),
        needle.end(),
        [](char a, char b) noexcept {
            return std::tolower(static_cast<unsigned char>(a)) ==
                   std::tolower(static_cast<unsigned char>(b));
        });
    return it != haystack.end();
}

[[nodiscard]] std::optional<std::uint64_t> parse_prefixed_hex_query(std::string_view query) noexcept {
    if (query.size() <= 2u || query[0] != '0' || (query[1] != 'x' && query[1] != 'X')) {
        return std::nullopt;
    }
    const std::string_view digits = query.substr(2u);
    if (digits.empty() || digits.front() == '+' || digits.front() == '-') {
        return std::nullopt;
    }
    std::uint64_t value = 0u;
    const char* begin = digits.data();
    const char* end = begin + digits.size();
    const auto [ptr, ec] = std::from_chars(begin, end, value, 16);
    if (ec == std::errc{} && ptr == end) {
        return value;
    }
    return std::nullopt;
}

[[nodiscard]] bool icontains_kind_tag(std::string_view tag, std::string_view needle) noexcept {
    if (icontains_ascii(tag, needle)) {
        return true;
    }
    if (needle.empty() || tag.size() < needle.size()) {
        return false;
    }
    const auto it = std::search(
        tag.begin(),
        tag.end(),
        needle.begin(),
        needle.end(),
        [](char a, char b) noexcept {
            if (a == ' ' && (b == '_' || b == '-')) {
                return true;
            }
            return std::tolower(static_cast<unsigned char>(a)) ==
                   std::tolower(static_cast<unsigned char>(b));
        });
    return it != tag.end();
}

[[nodiscard]] bool structure_node_matches_query(
    const StructureNode& node,
    std::string_view query,
    std::optional<std::uint64_t> exact_hex_value) {
    if (icontains_ascii(node.selection.label, query) ||
        icontains_kind_tag(selection_kind_tag(node.selection.kind), query) ||
        icontains_ascii(structure_node_badge(node.selection.kind), query)) {
        return true;
    }
    if (node.selection.virtual_address.has_value()) {
        const std::uint64_t va = *node.selection.virtual_address;
        if ((exact_hex_value.has_value() && *exact_hex_value == va) ||
            icontains_ascii(std::format("0x{:X}", va), query)) {
            return true;
        }
    }
    if (node.selection.file_offset.has_value()) {
        const std::uint64_t off = *node.selection.file_offset;
        if ((exact_hex_value.has_value() && *exact_hex_value == off) ||
            icontains_ascii(std::format("0x{:X}", off), query)) {
            return true;
        }
    }
    return false;
}

[[nodiscard]] std::optional<StructureNode> filter_node_recursive(
    const StructureNode& node,
    std::string_view query,
    std::optional<std::uint64_t> exact_hex_value) {
    if (node.selection.kind == SelectionKind::Group &&
        structure_node_matches_query(node, query, exact_hex_value)) {
        return node;
    }
    std::vector<StructureNode> filtered_children;
    filtered_children.reserve(node.children.size());
    for (const StructureNode& child : node.children) {
        if (auto matched = filter_node_recursive(child, query, exact_hex_value); matched.has_value()) {
            filtered_children.push_back(std::move(*matched));
        }
    }
    if (!filtered_children.empty()) {
        StructureNode out{
            .selection = node.selection,
            .children = std::move(filtered_children),
        };
        return out;
    }
    if (structure_node_matches_query(node, query, exact_hex_value)) {
        return node;
    }
    return std::nullopt;
}

[[nodiscard]] std::size_t count_matches_recursive(
    const StructureNode& node,
    std::string_view query,
    std::optional<std::uint64_t> exact_hex_value) {
    std::size_t total = structure_node_matches_query(node, query, exact_hex_value) ? 1u : 0u;
    for (const StructureNode& child : node.children) {
        total += count_matches_recursive(child, query, exact_hex_value);
    }
    return total;
}

[[nodiscard]] StructureNode group_node(std::string label) {
    return StructureNode{
        .selection = ViewerSelection{
            .kind = SelectionKind::Group,
            .label = std::move(label),
            .file_offset = std::nullopt,
            .virtual_address = std::nullopt,
            .size = 0,
            .object_index = 0,
            .preferred_view = PreferredView::Details
        },
        .children = {}
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
            .file_offset = std::nullopt,
            .virtual_address = std::nullopt,
            .size = 0,
            .object_index = object_index,
            .preferred_view = preferred_view
        },
        .children = {}
    };
}

[[nodiscard]] PreferredView section_view(const peelf::Section& section) {
    return section.executable ? PreferredView::Disassembly : PreferredView::Hex;
}

[[nodiscard]] std::string hex64(std::uint64_t value) {
    return std::format("{:X}", value);
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
        if (const peelf::PeClrHeader* clr = image.pe_clr_header()) {
            StructureNode clr_node = selectable_node(
                SelectionKind::ClrHeader, "CLR / .NET Metadata", 0, PreferredView::Details);
            clr_node.selection.file_offset = clr->file_offset;
            clr_node.selection.virtual_address =
                image.file_offset_to_virtual_address(clr->file_offset);
            clr_node.selection.size = clr->size;
            headers.children.push_back(std::move(clr_node));
        }
    } else if (image.macho_header() != nullptr) {
        StructureNode mh = selectable_node(SelectionKind::Header, "Mach-O Header", 1, PreferredView::Details);
        mh.selection.file_offset = 0;
        mh.selection.size = image.is_64bit() ? 32u : 28u;
        headers.children.push_back(std::move(mh));
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
        if (entry.import_by_ordinal) {
            label += "!#";
            label += std::to_string(entry.ordinal);
        } else if (!entry.name.empty()) {
            label += "!";
            label += entry.name;
        }
        if (entry.delay_load) {
            label += " (delay)";
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

    StructureNode bound_imports = group_node("Bound Imports");
    std::uint64_t bound_index = 0;
    for (const peelf::PeBoundImport& entry : image.pe_bound_imports()) {
        StructureNode node = selectable_node(SelectionKind::BoundImport,
                                             entry.module_name.empty() ? "Bound Import" : entry.module_name,
                                             bound_index,
                                             PreferredView::Details);
        node.selection.file_offset = entry.file_offset;
        node.selection.size = 8;
        bound_imports.children.push_back(std::move(node));
        ++bound_index;
    }
    root.children.push_back(std::move(bound_imports));

    if (const peelf::PeResourceDirectory* resource = image.pe_resource_directory()) {
        StructureNode node = selectable_node(SelectionKind::ResourceDirectory,
                                             "Resource Directory",
                                             0,
                                             PreferredView::Details);
        node.selection.file_offset = resource->file_offset;
        node.selection.virtual_address = image.file_offset_to_virtual_address(resource->file_offset);
        node.selection.size = 16u + static_cast<std::uint64_t>(resource->entries.size()) * 8u;
        std::uint64_t resource_data_index = 0;
        for (const peelf::PeResourceDataEntry& entry : image.pe_resource_data_entries()) {
            StructureNode data = selectable_node(SelectionKind::ResourceData,
                                                 "Resource " + std::to_string(entry.type_id) + "/" +
                                                     std::to_string(entry.name_id) + "/" +
                                                     std::to_string(entry.language_id),
                                                 resource_data_index,
                                                 PreferredView::Hex);
            data.selection.file_offset = entry.data_file_offset;
            data.selection.virtual_address = image.file_offset_to_virtual_address(entry.data_file_offset);
            data.selection.size = entry.size;
            node.children.push_back(std::move(data));
            ++resource_data_index;
        }
        root.children.push_back(std::move(node));
    }

    if (const peelf::PeClrHeader* clr = image.pe_clr_header()) {
        StructureNode node = selectable_node(SelectionKind::ClrHeader,
                                             "CLR Header",
                                             0,
                                             PreferredView::Details);
        node.selection.file_offset = clr->file_offset;
        node.selection.virtual_address = image.file_offset_to_virtual_address(clr->file_offset);
        node.selection.size = clr->size;
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

void NavigationHistory::visit(const ViewerSelection& selection) {
    if (!selection.virtual_address && !selection.file_offset) return;
    if (!entries_.empty()) {
        const auto& current = entries_[cursor_];
        if (current.virtual_address == selection.virtual_address && current.file_offset == selection.file_offset) {
            entries_[cursor_] = selection;
            return;
        }
        entries_.resize(cursor_ + 1);
    }
    if (entries_.size() == 256) entries_.erase(entries_.begin());
    entries_.push_back(selection);
    cursor_ = entries_.size() - 1;
}

std::optional<ViewerSelection> NavigationHistory::back() {
    if (!can_back()) return std::nullopt;
    return entries_[--cursor_];
}

std::optional<ViewerSelection> NavigationHistory::forward() {
    if (!can_forward()) return std::nullopt;
    return entries_[++cursor_];
}

void NavigationRequestQueue::enqueue(DeferredNavigationRequest request) {
    pending_.push_back(std::move(request));
}

void NavigationRequestQueue::enqueue_address(std::uint64_t address,
                                             PreferredView view,
                                             std::size_t highlight_size,
                                             bool request_decompile) {
    pending_.push_back(DeferredNavigationRequest{
        .kind = DeferredNavigationRequest::Kind::Address,
        .target = address,
        .preferred_view = view,
        .highlight_size = highlight_size,
        .request_decompile = request_decompile,
    });
}

void NavigationRequestQueue::enqueue_offset(std::uint64_t offset, std::size_t highlight_size) {
    pending_.push_back(DeferredNavigationRequest{
        .kind = DeferredNavigationRequest::Kind::Offset,
        .target = offset,
        .preferred_view = PreferredView::Hex,
        .highlight_size = highlight_size,
    });
}

void NavigationRequestQueue::enqueue_module(std::size_t module_index) {
    pending_.push_back(DeferredNavigationRequest{
        .kind = DeferredNavigationRequest::Kind::ModuleIndex,
        .target = static_cast<std::uint64_t>(module_index),
    });
}

void NavigationRequestQueue::enqueue_memory_region(std::size_t region_index,
                                                   bool prefer_module_context) {
    pending_.push_back(DeferredNavigationRequest{
        .kind = DeferredNavigationRequest::Kind::MemoryRegionIndex,
        .target = static_cast<std::uint64_t>(region_index),
        .prefer_module_context = prefer_module_context,
    });
}

void NavigationRequestQueue::enqueue_custom(std::function<void()> action) {
    if (!action) {
        return;
    }
    pending_.push_back(DeferredNavigationRequest{
        .kind = DeferredNavigationRequest::Kind::Custom,
        .custom_action = std::move(action),
    });
}

StructureNode build_structure_tree(const peelf::IBinaryImage& image) {
    StructureNode root{
        .selection = ViewerSelection{
            .kind = SelectionKind::Image,
            .label = std::string(peelf::to_string(image.format())) + " Image",
            .file_offset = std::nullopt,
            .virtual_address = image.entry_point(),
            .size = 0,
            .object_index = 0,
            .preferred_view = PreferredView::Details
        },
        .children = {}
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

namespace {

[[nodiscard]] StructureNode build_live_process_structure_tree_impl(
    const peelf::ProcessInfo& process,
    std::span<const peelf::ModuleInfo> modules,
    std::span<const peelf::MemoryRegion> regions,
    const peelf::IBinaryImage* active_image,
    std::optional<std::size_t> active_module_index,
    bool include_live_subtrees,
    std::span<const peelf::ThreadInfo> threads,
    std::span<const peelf::HandleInfo> handles,
    std::span<const peelf::SecurityFinding> findings) {
    std::string proc_label = "Process " +
        (process.name.empty() ? std::to_string(process.pid) : process.name) +
        " (PID " + std::to_string(process.pid) + ")";

    StructureNode root{
        .selection = ViewerSelection{
            .kind = SelectionKind::Process,
            .label = std::move(proc_label),
            .file_offset = std::nullopt,
            .virtual_address = active_image ? std::optional<std::uint64_t>(active_image->entry_point())
                                            : std::nullopt,
            .size = 0,
            .object_index = process.pid,
            .preferred_view = PreferredView::Details
        },
        .children = {}
    };

    StructureNode modules_group = group_node("Modules (" + std::to_string(modules.size()) + ")");
    for (std::size_t i = 0; i < modules.size(); ++i) {
        const peelf::ModuleInfo& mod = modules[i];
        std::string label = mod.name.empty() ? mod.path.string() : mod.name;
        if (label.empty()) {
            label = "module_0x" + hex64(mod.base_address);
        }
        if (active_module_index && *active_module_index == i) {
            label += " [active]";
        }
        label += " @ 0x" + hex64(mod.base_address);
        StructureNode mod_node = selectable_node(
            SelectionKind::ProcessModule,
            std::move(label),
            static_cast<std::uint64_t>(i),
            PreferredView::Details);
        mod_node.selection.virtual_address = mod.base_address;
        mod_node.selection.size = mod.size;
        modules_group.children.push_back(std::move(mod_node));
    }
    root.children.push_back(std::move(modules_group));

    StructureNode memmap_group = group_node("Memory Map (" + std::to_string(regions.size()) + ")");
    for (std::size_t i = 0; i < regions.size(); ++i) {
        const peelf::MemoryRegion& reg = regions[i];
        StructureNode reg_node{
            .selection = selection_from_memory_region(reg, static_cast<std::uint64_t>(i)),
            .children = {}
        };
        memmap_group.children.push_back(std::move(reg_node));
    }
    root.children.push_back(std::move(memmap_group));

    if (include_live_subtrees) {
        StructureNode threads_group = group_node("Threads (" + std::to_string(threads.size()) + ")");
        for (std::size_t i = 0; i < threads.size(); ++i) {
            threads_group.children.push_back(StructureNode{
                .selection = selection_from_process_thread(threads[i], static_cast<std::uint64_t>(i)),
                .children = {},
            });
        }
        root.children.push_back(std::move(threads_group));

        StructureNode handles_group = group_node("Handles / FDs (" + std::to_string(handles.size()) + ")");
        for (std::size_t i = 0; i < handles.size(); ++i) {
            handles_group.children.push_back(StructureNode{
                .selection = selection_from_process_handle(handles[i], static_cast<std::uint64_t>(i)),
                .children = {},
            });
        }
        root.children.push_back(std::move(handles_group));

        StructureNode findings_group = group_node("Security Findings (" + std::to_string(findings.size()) + ")");
        for (std::size_t i = 0; i < findings.size(); ++i) {
            findings_group.children.push_back(StructureNode{
                .selection = selection_from_security_finding(findings[i], static_cast<std::uint64_t>(i)),
                .children = {},
            });
        }
        root.children.push_back(std::move(findings_group));
    }

    if (active_image != nullptr) {
        StructureNode image_tree = build_structure_tree(*active_image);
        if (active_module_index && *active_module_index < modules.size() &&
            !modules[*active_module_index].name.empty()) {
            image_tree.selection.label =
                modules[*active_module_index].name + " (" + image_tree.selection.label + ")";
        }
        root.children.push_back(std::move(image_tree));
    }

    return root;
}

} // namespace

std::string_view selection_kind_tag(SelectionKind kind) noexcept {
    switch (kind) {
        case SelectionKind::None:              return "None";
        case SelectionKind::Image:             return "Image";
        case SelectionKind::Header:            return "Header";
        case SelectionKind::Section:           return "Section";
        case SelectionKind::Segment:           return "Segment";
        case SelectionKind::Import:            return "Import";
        case SelectionKind::Export:            return "Export";
        case SelectionKind::Symbol:            return "Symbol";
        case SelectionKind::Relocation:        return "Relocation";
        case SelectionKind::DebugDirectory:    return "Debug Directory";
        case SelectionKind::RuntimeFunction:   return "Runtime Function";
        case SelectionKind::TlsDirectory:      return "TLS Directory";
        case SelectionKind::Certificate:       return "Certificate";
        case SelectionKind::LoadConfig:        return "Load Config";
        case SelectionKind::BoundImport:       return "Bound Import";
        case SelectionKind::ResourceDirectory: return "Resource Directory";
        case SelectionKind::ResourceData:      return "Resource Data";
        case SelectionKind::ClrHeader:         return "CLR Header";
        case SelectionKind::DynamicEntry:      return "Dynamic Entry";
        case SelectionKind::Note:              return "Note";
        case SelectionKind::HashTable:         return "Hash Table";
        case SelectionKind::Interpreter:       return "Interpreter";
        case SelectionKind::CallGraphNode:     return "Call Graph Node";
        case SelectionKind::Patch:             return "Patch";
        case SelectionKind::ByteRange:         return "Bytes";
        case SelectionKind::Process:           return "Process";
        case SelectionKind::ProcessModule:     return "Process Module";
        case SelectionKind::MemoryRegion:      return "Memory Region";
        case SelectionKind::Group:             return "Group";
        case SelectionKind::ProcessThread:     return "Process Thread";
        case SelectionKind::ProcessHandle:     return "Process Handle";
        case SelectionKind::SecurityFinding:   return "Security Finding";
    }
    return "Unknown";
}

std::string_view structure_node_badge(SelectionKind kind) noexcept {
    switch (kind) {
        case SelectionKind::None:              return "";
        case SelectionKind::Image:             return "[IMG]";
        case SelectionKind::Header:            return "[HDR]";
        case SelectionKind::Section:           return "[SEC]";
        case SelectionKind::Segment:           return "[SEG]";
        case SelectionKind::Import:            return "[IMP]";
        case SelectionKind::Export:            return "[EXP]";
        case SelectionKind::Symbol:            return "[SYM]";
        case SelectionKind::Relocation:        return "[REL]";
        case SelectionKind::DebugDirectory:    return "[DBG]";
        case SelectionKind::RuntimeFunction:   return "[RTF]";
        case SelectionKind::TlsDirectory:      return "[TLS]";
        case SelectionKind::Certificate:       return "[CRT]";
        case SelectionKind::LoadConfig:        return "[CFG]";
        case SelectionKind::BoundImport:       return "[BND]";
        case SelectionKind::ResourceDirectory: return "[RES]";
        case SelectionKind::ResourceData:      return "[RES]";
        case SelectionKind::ClrHeader:         return "[CLR]";
        case SelectionKind::DynamicEntry:      return "[DYN]";
        case SelectionKind::Note:              return "[NOTE]";
        case SelectionKind::HashTable:         return "[HASH]";
        case SelectionKind::Interpreter:       return "[INTP]";
        case SelectionKind::CallGraphNode:     return "[NODE]";
        case SelectionKind::Patch:             return "[PTCH]";
        case SelectionKind::ByteRange:         return "[BYTE]";
        case SelectionKind::Process:           return "[PROC]";
        case SelectionKind::ProcessModule:     return "[MOD]";
        case SelectionKind::MemoryRegion:      return "[MEM]";
        case SelectionKind::Group:             return "[GRP]";
        case SelectionKind::ProcessThread:     return "[THR]";
        case SelectionKind::ProcessHandle:     return "[HND]";
        case SelectionKind::SecurityFinding:   return "[SEC!]";
    }
    return "";
}

std::optional<StructureNode> filter_structure_tree(
    const StructureNode& root,
    std::string_view query) {
    const std::string_view trimmed = trim_query_whitespace(query);
    if (trimmed.empty()) {
        return root;
    }
    const std::optional<std::uint64_t> exact_hex = parse_prefixed_hex_query(trimmed);
    return filter_node_recursive(root, trimmed, exact_hex);
}

std::size_t count_structure_tree_matches(
    const StructureNode& root,
    std::string_view query) {
    const std::string_view trimmed = trim_query_whitespace(query);
    if (trimmed.empty()) {
        return 0u;
    }
    const std::optional<std::uint64_t> exact_hex = parse_prefixed_hex_query(trimmed);
    return count_matches_recursive(root, trimmed, exact_hex);
}

StructureNode build_live_process_structure_tree(
    const peelf::ProcessInfo& process,
    std::span<const peelf::ModuleInfo> modules,
    std::span<const peelf::MemoryRegion> regions,
    const peelf::IBinaryImage* active_image,
    std::optional<std::size_t> active_module_index) {
    return build_live_process_structure_tree_impl(
        process,
        modules,
        regions,
        active_image,
        active_module_index,
        false,
        {},
        {},
        {});
}

StructureNode build_live_process_structure_tree(
    const peelf::ProcessInfo& process,
    std::span<const peelf::ModuleInfo> modules,
    std::span<const peelf::MemoryRegion> regions,
    const peelf::IBinaryImage* active_image,
    std::optional<std::size_t> active_module_index,
    std::span<const peelf::ThreadInfo> threads,
    std::span<const peelf::HandleInfo> handles,
    std::span<const peelf::SecurityFinding> findings) {
    return build_live_process_structure_tree_impl(
        process,
        modules,
        regions,
        active_image,
        active_module_index,
        true,
        threads,
        handles,
        findings);
}

ViewerSelection selection_from_call_graph_node(const CallGraphNode& node,
                                               const peelf::IBinaryImage& image) {
    std::optional<std::uint64_t> file_offset = node.bytes.start.file_offset;
    if (!file_offset && node.bytes.start.virtual_address) {
        file_offset = image.virtual_address_to_file_offset(*node.bytes.start.virtual_address);
    }

    PreferredView preferred_view = PreferredView::Details;
    if (file_offset && (node.kind == CallGraphNodeKind::Function ||
                        node.kind == CallGraphNodeKind::BasicBlock ||
                        node.kind == CallGraphNodeKind::Instruction ||
                        node.kind == CallGraphNodeKind::Unknown)) {
        preferred_view = PreferredView::Disassembly;
    } else if (file_offset) {
        preferred_view = PreferredView::Hex;
    }

    return ViewerSelection{
        .kind = SelectionKind::CallGraphNode,
        .label = node.label.empty() ? node.id : node.label,
        .file_offset = file_offset,
        .virtual_address = node.bytes.start.virtual_address,
        .size = node.bytes.size,
        .object_index = node.symbol ? node.symbol->symbol_index : 0u,
        .preferred_view = preferred_view,
    };
}

ViewerSelection selection_from_patch_interval(const peelf::PatchInterval& patch,
                                              std::uint64_t patch_index) {
    return ViewerSelection{
        .kind = SelectionKind::Patch,
        .label = "Patch 0x" + hex64(patch.offset),
        .file_offset = patch.offset,
        .virtual_address = std::nullopt,
        .size = static_cast<std::uint64_t>(patch.patched.size()),
        .object_index = patch_index,
        .preferred_view = PreferredView::Hex
    };
}

ViewerSelection selection_from_live_patch_interval(const peelf::PatchInterval& patch,
                                                   std::uint64_t patch_index,
                                                   std::optional<std::uint64_t> window_offset,
                                                   std::string_view prefix) {
    std::string label(prefix);
    if (!label.empty()) {
        label += ' ';
    }
    label += "RAM Patch 0x" + hex64(patch.offset);
    return ViewerSelection{
        .kind = SelectionKind::Patch,
        .label = std::move(label),
        .file_offset = window_offset,
        .virtual_address = patch.offset,
        .size = static_cast<std::uint64_t>(patch.patched.size()),
        .object_index = patch_index,
        .preferred_view = PreferredView::Hex
    };
}

ViewerSelection selection_from_memory_region(const peelf::MemoryRegion& region,
                                             std::uint64_t region_index,
                                             std::optional<std::uint64_t> window_offset) {
    std::string label = "0x" + hex64(region.start_address) + " " +
                        peelf::format_protection(region.protection);
    if (!region.pathname.empty()) {
        label += " " + region.pathname;
    } else {
        label += " (" + std::string(peelf::to_string(region.kind)) + ")";
    }
    return ViewerSelection{
        .kind = SelectionKind::MemoryRegion,
        .label = std::move(label),
        .file_offset = window_offset,
        .virtual_address = region.start_address,
        .size = region.size(),
        .object_index = region_index,
        .preferred_view = region.protection.executable ? PreferredView::Disassembly : PreferredView::Hex
    };
}

ViewerSelection selection_from_process_thread(const peelf::ThreadInfo& thread,
                                              std::uint64_t thread_index) {
    std::string label = std::format("TID {}", thread.tid);
    if (!thread.name.empty()) {
        label += std::format(" ({})", thread.name);
    }
    label += std::format(" [{}]", peelf::to_string(thread.state));
    const std::optional<std::uint64_t> va = thread.instruction_pointer.has_value()
        ? thread.instruction_pointer
        : thread.start_address;
    if (va.has_value()) {
        label += std::format(" @ 0x{:X}", *va);
    }
    return ViewerSelection{
        .kind = SelectionKind::ProcessThread,
        .label = std::move(label),
        .file_offset = std::nullopt,
        .virtual_address = va,
        .size = va.has_value() ? 1u : 0u,
        .object_index = thread_index,
        .preferred_view = va.has_value() ? PreferredView::Disassembly : PreferredView::Details,
    };
}

ViewerSelection selection_from_process_handle(const peelf::HandleInfo& handle,
                                              std::uint64_t handle_index) {
    const std::string_view kind_str =
        !handle.type_name.empty() ? std::string_view{handle.type_name} : peelf::to_string(handle.kind);
    std::string label = std::format("0x{:X} [{}]", handle.handle_or_fd, kind_str);
    if (!handle.target.empty()) {
        label += ' ';
        label += handle.target;
    }
    return ViewerSelection{
        .kind = SelectionKind::ProcessHandle,
        .label = std::move(label),
        .file_offset = std::nullopt,
        .virtual_address = std::nullopt,
        .size = 0u,
        .object_index = handle_index,
        .preferred_view = PreferredView::Details,
    };
}

ViewerSelection selection_from_security_finding(const peelf::SecurityFinding& finding,
                                                std::uint64_t finding_index) {
    std::string label = std::format("[{}] {}: {}",
                                    peelf::to_string(finding.severity),
                                    finding.rule_id,
                                    finding.rule_name);
    if (!finding.subject.empty()) {
        label += std::format(" ({})", finding.subject);
    }
    PreferredView preferred_view = PreferredView::Details;
    if (finding.virtual_address.has_value()) {
        preferred_view = PreferredView::Disassembly;
    } else if (finding.file_offset.has_value()) {
        preferred_view = PreferredView::Hex;
    }
    return ViewerSelection{
        .kind = SelectionKind::SecurityFinding,
        .label = std::move(label),
        .file_offset = finding.file_offset,
        .virtual_address = finding.virtual_address,
        .size = (finding.virtual_address.has_value() || finding.file_offset.has_value()) ? 1u : 0u,
        .object_index = finding_index,
        .preferred_view = preferred_view,
    };
}

ViewerSelection selection_from_symbol_record(const SymbolRecord& record,
                                             std::uint64_t record_index) {
    PreferredView view = PreferredView::Details;
    if (record.file_offset) {
        view = record.source == SymbolSource::Import ? PreferredView::Hex : PreferredView::Disassembly;
    }
    return ViewerSelection{
        .kind = SelectionKind::Symbol,
        .label = record.name.empty() ? "<unnamed>" : record.name,
        .file_offset = record.file_offset,
        .virtual_address = record.virtual_address,
        .size = record.size != 0 ? record.size : 1u,
        .object_index = record_index,
        .preferred_view = view
    };
}

std::optional<std::uint64_t> selected_symbol_index(const ViewerSelection& selection,
                                                   const peelf::IBinaryImage& image) {
    if (selection.kind != SelectionKind::Symbol && selection.kind != SelectionKind::CallGraphNode) {
        return std::nullopt;
    }
    if (selection.object_index >= image.symbols().size()) {
        return std::nullopt;
    }

    const peelf::Symbol& symbol = image.symbols()[static_cast<std::size_t>(selection.object_index)];
    if (selection.kind == SelectionKind::Symbol) {
        return selection.object_index;
    }
    if (!selection.label.empty() && selection.label == symbol.name) {
        return selection.object_index;
    }
    if (selection.virtual_address && *selection.virtual_address == symbol.virtual_address) {
        return selection.object_index;
    }
    return std::nullopt;
}

std::optional<std::uint64_t> selected_symbol_record_index(const ViewerSelection& selection,
                                                          const SymbolIndex& symbol_index) {
    const auto records = symbol_index.records();
    if (selection.kind != SelectionKind::Symbol && selection.kind != SelectionKind::CallGraphNode &&
        selection.kind != SelectionKind::Export && selection.kind != SelectionKind::Import) {
        return std::nullopt;
    }
    if (selection.kind == SelectionKind::Symbol && selection.object_index < records.size()) {
        const SymbolRecord& rec = records[static_cast<std::size_t>(selection.object_index)];
        if (rec.name == selection.label ||
            (selection.virtual_address && rec.virtual_address == selection.virtual_address)) {
            return selection.object_index;
        }
    }
    for (std::size_t i = 0; i < records.size(); ++i) {
        const SymbolRecord& rec = records[i];
        if (!selection.label.empty() && rec.name == selection.label) {
            return static_cast<std::uint64_t>(i);
        }
        if (selection.virtual_address && rec.virtual_address == selection.virtual_address) {
            return static_cast<std::uint64_t>(i);
        }
    }
    return std::nullopt;
}

} // namespace viewer
