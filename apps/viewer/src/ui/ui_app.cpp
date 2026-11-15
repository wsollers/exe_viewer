#include "ui_app.hpp"
#include <imgui.h>
#include <imgui_internal.h>

#include <algorithm>
#include <array>
#include <cctype>
#include <cinttypes>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <format>
#include <fstream>
#include <limits>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <peelf/process.hpp>

#include "graph/call_graph.hpp"
#include "logger.hpp"
#include "symbols/debug_symbols.hpp"

namespace viewer {
namespace {

[[nodiscard]] std::optional<viewer::Architecture> disassembler_architecture(peelf::Architecture arch) {
    switch (arch) {
        case peelf::Architecture::X86:       return viewer::Architecture::X86_32;
        case peelf::Architecture::X86_64:    return viewer::Architecture::X86_64;
        case peelf::Architecture::ARM:       return viewer::Architecture::ARM32;
        case peelf::Architecture::ARM64:     return viewer::Architecture::ARM64;
        case peelf::Architecture::MIPS32:    return viewer::Architecture::MIPS32;
        case peelf::Architecture::MIPS64:    return viewer::Architecture::MIPS64;
        case peelf::Architecture::PowerPC:   return viewer::Architecture::PowerPC32;
        case peelf::Architecture::PowerPC64: return viewer::Architecture::PowerPC64;
        case peelf::Architecture::RISCV32:   return viewer::Architecture::RISCV32;
        case peelf::Architecture::RISCV64:   return viewer::Architecture::RISCV64;
        default:                             return std::nullopt;
    }
}

[[nodiscard]] viewer::Endianness disassembler_endianness(peelf::Endianness endianness) {
    return endianness == peelf::Endianness::Big ? viewer::Endianness::Big : viewer::Endianness::Little;
}

[[nodiscard]] bool same_selection(const ViewerSelection& lhs, const ViewerSelection& rhs) {
    return lhs.kind == rhs.kind &&
           lhs.object_index == rhs.object_index &&
           lhs.file_offset == rhs.file_offset &&
           lhs.virtual_address == rhs.virtual_address &&
           lhs.label == rhs.label;
}

[[nodiscard]] std::size_t clamp_to_size_t(std::uint64_t value) noexcept {
    if (value > static_cast<std::uint64_t>(std::numeric_limits<std::size_t>::max())) {
        return std::numeric_limits<std::size_t>::max();
    }
    return static_cast<std::size_t>(value);
}

[[nodiscard]] bool icontains_filter(std::string_view haystack, std::string_view needle) {
    if (needle.empty()) {
        return true;
    }
    const auto it = std::search(
        haystack.begin(),
        haystack.end(),
        needle.begin(),
        needle.end(),
        [](char a, char b) {
            return std::tolower(static_cast<unsigned char>(a)) ==
                   std::tolower(static_cast<unsigned char>(b));
        });
    return it != haystack.end();
}

struct BmpImage {
    std::uint32_t width = 0;
    std::uint32_t height = 0;
    std::vector<std::uint8_t> rgba;
};

struct GraphLayoutBounds {
    double min_x = 0.0;
    double min_y = 0.0;
    double max_x = 0.0;
    double max_y = 0.0;
};

[[nodiscard]] std::string format_graph_hex(std::uint64_t value) {
    std::array<char, 32> buffer{};
    std::snprintf(buffer.data(), buffer.size(), "0x%llX", static_cast<unsigned long long>(value));
    return buffer.data();
}

[[nodiscard]] std::string call_graph_node_display_label(const CallGraphNode& node) {
    const std::string base_label = node.label.empty() ? node.id : node.label;
    std::string label = base_label;
    if (node.bytes.start.virtual_address) {
        label += "\nVA " + format_graph_hex(*node.bytes.start.virtual_address);
    }
    if (node.bytes.start.file_offset) {
        label += "\nfile " + format_graph_hex(*node.bytes.start.file_offset);
    }
    if (node.symbol && !node.symbol->name.empty() && node.symbol->name != base_label) {
        label += "\n" + node.symbol->name;
    }
    return label;
}

[[nodiscard]] GraphLayoutBounds graph_layout_bounds(const GraphLayout& layout) {
    if (layout.nodes.empty()) {
        return {.min_x = 0.0, .min_y = 0.0, .max_x = layout.width, .max_y = layout.height};
    }

    GraphLayoutBounds bounds{
        .min_x = layout.nodes.front().center_x - layout.nodes.front().width * 0.5,
        .min_y = layout.nodes.front().center_y - layout.nodes.front().height * 0.5,
        .max_x = layout.nodes.front().center_x + layout.nodes.front().width * 0.5,
        .max_y = layout.nodes.front().center_y + layout.nodes.front().height * 0.5,
    };

    for (const GraphLayoutNode& node : layout.nodes) {
        bounds.min_x = std::min(bounds.min_x, node.center_x - node.width * 0.5);
        bounds.min_y = std::min(bounds.min_y, node.center_y - node.height * 0.5);
        bounds.max_x = std::max(bounds.max_x, node.center_x + node.width * 0.5);
        bounds.max_y = std::max(bounds.max_y, node.center_y + node.height * 0.5);
    }
    return bounds;
}

[[nodiscard]] std::uint16_t read_u16_le(const std::vector<std::uint8_t>& bytes, std::size_t offset) {
    return static_cast<std::uint16_t>(bytes[offset] | (bytes[offset + 1] << 8u));
}

[[nodiscard]] std::uint32_t read_u32_le(const std::vector<std::uint8_t>& bytes, std::size_t offset) {
    return static_cast<std::uint32_t>(bytes[offset] |
                                      (bytes[offset + 1] << 8u) |
                                      (bytes[offset + 2] << 16u) |
                                      (bytes[offset + 3] << 24u));
}

[[nodiscard]] std::int32_t read_i32_le(const std::vector<std::uint8_t>& bytes, std::size_t offset) {
    return static_cast<std::int32_t>(read_u32_le(bytes, offset));
}

[[nodiscard]] std::optional<std::vector<std::uint8_t>> read_binary_file(const std::filesystem::path& path) {
    std::ifstream file(path, std::ios::binary | std::ios::ate);
    if (!file) {
        return std::nullopt;
    }

    const std::streamoff end = file.tellg();
    if (end < 0) {
        return std::nullopt;
    }

    std::vector<std::uint8_t> bytes(static_cast<std::size_t>(end));
    file.seekg(0, std::ios::beg);
    if (!bytes.empty()) {
        file.read(reinterpret_cast<char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
        if (!file) {
            return std::nullopt;
        }
    }
    return bytes;
}

[[nodiscard]] std::optional<std::string> read_text_file(const std::filesystem::path& path) {
    const std::optional<std::vector<std::uint8_t>> bytes = read_binary_file(path);
    if (!bytes) {
        return std::nullopt;
    }
    return std::string(reinterpret_cast<const char*>(bytes->data()), bytes->size());
}

[[nodiscard]] std::optional<BmpImage> load_bmp_rgba(const std::filesystem::path& path) {
    const std::optional<std::vector<std::uint8_t>> loaded_bytes = read_binary_file(path);
    if (!loaded_bytes) {
        return std::nullopt;
    }
    const std::vector<std::uint8_t>& bytes = *loaded_bytes;
    if (bytes.size() < 54 || bytes[0] != 'B' || bytes[1] != 'M') {
        return std::nullopt;
    }

    const std::uint32_t pixel_offset = read_u32_le(bytes, 10);
    const std::uint32_t dib_size = read_u32_le(bytes, 14);
    if (dib_size < 40 || pixel_offset >= bytes.size()) {
        return std::nullopt;
    }

    const std::int32_t raw_width = read_i32_le(bytes, 18);
    const std::int32_t raw_height = read_i32_le(bytes, 22);
    const std::uint16_t planes = read_u16_le(bytes, 26);
    const std::uint16_t bits_per_pixel = read_u16_le(bytes, 28);
    const std::uint32_t compression = read_u32_le(bytes, 30);
    if (raw_width <= 0 || raw_height == 0 || planes != 1 || compression != 0 ||
        (bits_per_pixel != 24 && bits_per_pixel != 32)) {
        return std::nullopt;
    }

    const bool top_down = raw_height < 0;
    const std::uint32_t width = static_cast<std::uint32_t>(raw_width);
    const std::uint32_t height = static_cast<std::uint32_t>(top_down ? -raw_height : raw_height);
    const std::uint32_t bytes_per_pixel = bits_per_pixel / 8u;
    const std::uint32_t source_stride = ((width * bytes_per_pixel + 3u) / 4u) * 4u;
    if (pixel_offset + static_cast<std::size_t>(source_stride) * height > bytes.size()) {
        return std::nullopt;
    }

    BmpImage image{
        .width = width,
        .height = height,
        .rgba = std::vector<std::uint8_t>(static_cast<std::size_t>(width) * height * 4u),
    };

    for (std::uint32_t y = 0; y < height; ++y) {
        const std::uint32_t source_y = top_down ? y : (height - 1u - y);
        const std::size_t source_row = pixel_offset + static_cast<std::size_t>(source_y) * source_stride;
        const std::size_t dest_row = static_cast<std::size_t>(y) * width * 4u;
        for (std::uint32_t x = 0; x < width; ++x) {
            const std::size_t source = source_row + static_cast<std::size_t>(x) * bytes_per_pixel;
            const std::size_t dest = dest_row + static_cast<std::size_t>(x) * 4u;
            image.rgba[dest + 0] = bytes[source + 2];
            image.rgba[dest + 1] = bytes[source + 1];
            image.rgba[dest + 2] = bytes[source + 0];
            image.rgba[dest + 3] = bits_per_pixel == 32 ? bytes[source + 3] : 255u;
        }
    }
    return image;
}

[[nodiscard]] std::optional<std::filesystem::path> find_graphs_dir() {
    std::filesystem::path current = std::filesystem::current_path();
    for (std::uint32_t depth = 0; depth < 10; ++depth) {
        const std::array<std::filesystem::path, 2> candidates{
            current / "out" / "graphs",
            current / "apps" / "viewer" / "assets" / "graphs",
        };
        for (const std::filesystem::path& candidate : candidates) {
            if (std::filesystem::exists(candidate)) {
                return candidate;
            }
        }
        if (!current.has_parent_path() || current == current.parent_path()) {
            break;
        }
        current = current.parent_path();
    }
    return std::nullopt;
}

[[nodiscard]] const char* graph_dot_name(UiApp::CallGraphSample sample) {
    switch (sample) {
        case UiApp::CallGraphSample::LoadedImage:
            return "loaded_image_call_graph.dot";
        case UiApp::CallGraphSample::PeStartup:
            return "pe_x64_startup_to_winmain.dot";
        case UiApp::CallGraphSample::ElfStartup:
            return "linux_elf_startup_to_main.dot";
    }
    return "pe_x64_startup_to_winmain.dot";
}

[[nodiscard]] const char* graph_bmp_name(UiApp::CallGraphSample sample) {
    switch (sample) {
        case UiApp::CallGraphSample::LoadedImage:
            return "loaded_image_call_graph.bmp";
        case UiApp::CallGraphSample::PeStartup:
            return "pe_x64_startup_to_winmain.bmp";
        case UiApp::CallGraphSample::ElfStartup:
            return "linux_elf_startup_to_main.bmp";
    }
    return "pe_x64_startup_to_winmain.bmp";
}

} // namespace

UiApp::UiApp(BinaryModel& model, VulkanManager& vulkan)
    : model_(model)
    , vulkan_(vulkan)
    , file_panel_(model)
    , memory_map_panel_(model, current_selection_)
    , structure_panel_(structure_tree_, current_selection_)
    , details_panel_(current_selection_)
    , sections_panel_(model)
    , hex_panel_(model)
    , patch_set_panel_(model, current_selection_)
    , shellcode_panel_(model, current_selection_)
    , imports_panel_(model)
    , exports_panel_(model)
    , symbols_panel_(model, current_selection_)
    , log_panel_()
    , pe_headers_panel_(model)
    , pe_imports_panel_(model)
    , pe_exports_panel_(model)
{
    hex_panel_.set_byte_activated_callback([this](std::size_t off) {
        const std::optional<std::uint64_t> va = model_.offset_to_virtual_address(off);
        current_selection_ = ViewerSelection{
            .kind = SelectionKind::None,
            .label = va ? std::format("VA 0x{:X}", *va) : std::format("Offset 0x{:X}", off),
            .file_offset = off,
            .virtual_address = va,
            .size = 1,
            .preferred_view = PreferredView::Hex,
        };
        last_navigation_selection_ = current_selection_;
        disassemble_at_offset(off);
    });
    hex_panel_.set_bytes_patched_callback([this](std::size_t) {
        refresh_disassembly();
    });

    auto on_refresh_map = [this]() {
        auto res = model_.refresh_process_map();
        if (!res) {
            Log().error("Failed to refresh process memory map: {}", res.error().message);
            return;
        }
        sync_live_process_view(false);
        Log().info("Refreshed process memory map ({} regions, {} modules)",
                   model_.memory_regions().size(),
                   model_.process_modules().size());
    };
    auto on_detach_proc = [this]() {
        model_.detach_process();
        on_file_loaded();
        Log().info("Detached from live process");
    };

    file_panel_.set_attach_requested_callback([this]() { open_attach_process_modal(); });
    file_panel_.set_refresh_requested_callback(on_refresh_map);
    file_panel_.set_detach_requested_callback(on_detach_proc);

    memory_map_panel_.set_attach_requested_callback([this]() {
        open_attach_process_modal();
    });
    memory_map_panel_.set_refresh_requested_callback(on_refresh_map);
    memory_map_panel_.set_detach_requested_callback(on_detach_proc);
    memory_map_panel_.set_module_selected_callback([this](std::size_t module_index) {
        auto res = model_.select_process_module(module_index);
        if (!res) {
            Log().error("Failed to select module: {}", res.error().message);
            return;
        }
        sync_live_process_view(true);
    });
    memory_map_panel_.set_region_activated_callback([this](std::size_t region_index, bool prefer_module_context) {
        if (region_index >= model_.memory_regions().size()) {
            return;
        }
        const peelf::MemoryRegion reg_copy = model_.memory_regions()[region_index];
        auto res = model_.select_memory_region(region_index, prefer_module_context);
        if (!res) {
            Log().error("Failed to select memory region: {}", res.error().message);
            return;
        }
        sync_live_process_view(false);
        const std::uint64_t offset = model_.virtual_address_to_offset(reg_copy.start_address).value_or(0u);
        current_selection_ = selection_from_memory_region(reg_copy, static_cast<std::uint64_t>(region_index), offset);
        hex_panel_.navigate_to_range(clamp_to_size_t(offset),
                                     clamp_to_size_t(std::min<std::uint64_t>(reg_copy.size(), 16u)));
        if (reg_copy.protection.executable) {
            disassemble_at_offset(offset, reg_copy.start_address);
        }
        last_navigation_selection_ = current_selection_;
    });

    patch_set_panel_.set_patch_activated_callback([this](const ViewerSelection& sel) {
        std::optional<std::uint64_t> off = sel.file_offset;
        if (!off && sel.virtual_address) {
            if (model_.is_live_process() && !model_.virtual_address_to_offset(*sel.virtual_address)) {
                if (model_.navigate_to_virtual_address(*sel.virtual_address)) {
                    sync_live_process_view(false);
                }
            }
            off = model_.virtual_address_to_offset(*sel.virtual_address);
        }
        if (off) {
            const std::uint64_t sz = sel.size != 0 ? sel.size : 1u;
            hex_panel_.navigate_to_range(clamp_to_size_t(*off), clamp_to_size_t(sz));
            disassemble_at_offset(*off, sel.virtual_address.value_or(*off));
        }
        last_navigation_selection_ = sel;
    });
    patch_set_panel_.set_patch_mutated_callback([this]() {
        refresh_disassembly();
    });
    shellcode_panel_.set_patch_changed_callback([this]() {
        refresh_disassembly();
    });

    sections_panel_.set_section_activated_callback(
        [this](const peelf::Section& section, std::uint64_t object_index) {
            const std::optional<std::uint64_t> nav_offset =
                model_.is_live_process()
                    ? model_.virtual_address_to_offset(section.virtual_address)
                    : std::optional<std::uint64_t>(section.file_offset);
            if (!nav_offset) {
                Log().warn("Section '{}' at 0x{:X} is outside the active window",
                           section.name,
                           section.virtual_address);
                return;
            }
            const std::uint64_t range_size = section.file_size != 0 ? section.file_size : section.virtual_size;
            current_selection_ = ViewerSelection{
                .kind = SelectionKind::Section,
                .label = section.name,
                .file_offset = *nav_offset,
                .virtual_address = section.virtual_address,
                .size = std::max(section.file_size, section.virtual_size),
                .object_index = object_index,
                .preferred_view = section.executable ? PreferredView::Disassembly : PreferredView::Hex
            };
            hex_panel_.navigate_to_range(clamp_to_size_t(*nav_offset),
                                         clamp_to_size_t(std::max<std::uint64_t>(range_size, 1u)));
            if (section.executable) {
                disassemble_at_offset(*nav_offset, section.virtual_address);
            }
            last_navigation_selection_ = current_selection_;
        });
    symbols_panel_.set_symbol_record_activated_callback([this](const SymbolRecord& record, std::uint64_t object_index) {
        std::optional<std::uint64_t> nav_offset = record.file_offset;
        if (record.virtual_address) {
            const auto model_off = model_.virtual_address_to_offset(*record.virtual_address);
            if (model_off) {
                nav_offset = model_off;
            } else if (model_.is_live_process() && model_.navigate_to_virtual_address(*record.virtual_address)) {
                sync_live_process_view(false);
                nav_offset = model_.virtual_address_to_offset(*record.virtual_address);
            }
        }
        if (!nav_offset) {
            Log().warn("Symbol '{}' at 0x{:X} does not map to readable bytes",
                       record.name.empty() ? "<unnamed>" : record.name,
                       record.virtual_address.value_or(0u));
            return;
        }

        const std::uint64_t highlight_size = record.size != 0 ? record.size : 1u;
        current_selection_ = selection_from_symbol_record(record, object_index);
        current_selection_.file_offset = *nav_offset;
        hex_panel_.navigate_to_range(clamp_to_size_t(*nav_offset), clamp_to_size_t(highlight_size));
        if (current_selection_.preferred_view == PreferredView::Disassembly) {
            disassemble_at_offset(*nav_offset, record.virtual_address.value_or(*nav_offset));
        }
        last_navigation_selection_ = current_selection_;
    });
    imports_panel_.set_import_activated_callback([this](const peelf::ImportEntry& entry, std::uint64_t object_index) {
        const peelf::IBinaryImage* img = model_.image();
        if (img == nullptr || entry.address == 0) {
            return;
        }

        std::optional<std::uint64_t> nav_offset = model_.virtual_address_to_offset(entry.address);
        if (!nav_offset && model_.is_live_process() && model_.navigate_to_virtual_address(entry.address)) {
            sync_live_process_view(false);
            nav_offset = model_.virtual_address_to_offset(entry.address);
        }
        if (!nav_offset) {
            Log().warn("Import '{}!{}' at 0x{:X} does not map to bytes",
                       entry.library,
                       entry.name.empty() ? "<ordinal-or-library>" : entry.name,
                       entry.address);
            return;
        }

        const std::uint64_t pointer_size = img->is_64bit() ? 8u : 4u;
        std::string label = entry.library;
        if (!entry.name.empty()) {
            label += "!";
            label += entry.name;
        }
        current_selection_ = ViewerSelection{
            .kind = SelectionKind::Import,
            .label = std::move(label),
            .file_offset = *nav_offset,
            .virtual_address = entry.address,
            .size = pointer_size,
            .object_index = object_index,
            .preferred_view = PreferredView::Hex
        };
        hex_panel_.navigate_to_range(clamp_to_size_t(*nav_offset), clamp_to_size_t(pointer_size));
        last_navigation_selection_ = current_selection_;
    });
    exports_panel_.set_export_activated_callback([this](const peelf::ExportEntry& entry, std::uint64_t object_index) {
        const peelf::IBinaryImage* img = model_.image();
        if (img == nullptr || entry.virtual_address == 0) {
            return;
        }

        std::optional<std::uint64_t> nav_offset = model_.virtual_address_to_offset(entry.virtual_address);
        if (!nav_offset && model_.is_live_process() && model_.navigate_to_virtual_address(entry.virtual_address)) {
            sync_live_process_view(false);
            nav_offset = model_.virtual_address_to_offset(entry.virtual_address);
        }
        if (!nav_offset) {
            Log().warn("Export '{}' at 0x{:X} does not map to bytes",
                       entry.name.empty() ? "<unnamed>" : entry.name,
                       entry.virtual_address);
            return;
        }

        current_selection_ = ViewerSelection{
            .kind = SelectionKind::Export,
            .label = entry.name.empty() ? "<unnamed>" : entry.name,
            .file_offset = *nav_offset,
            .virtual_address = entry.virtual_address,
            .size = 1,
            .object_index = object_index,
            .preferred_view = PreferredView::Disassembly
        };
        hex_panel_.navigate_to_range(clamp_to_size_t(*nav_offset), 1);
        disassemble_at_offset(*nav_offset, entry.virtual_address);
        last_navigation_selection_ = current_selection_;
    });
}

UiApp::~UiApp() {
    if (call_graph_texture_) {
        vulkan_.destroy_texture(*call_graph_texture_);
        call_graph_texture_.reset();
    }
}

void UiApp::render() {
    render_main_menu();
    render_dockspace();
    render_attach_process_modal();

    file_panel_.draw();
    memory_map_panel_.draw();
    structure_panel_.draw();
    apply_structure_selection_navigation();
    details_panel_.draw();
    sections_panel_.draw();
    hex_panel_.draw();
    patch_set_panel_.draw();
    shellcode_panel_.draw();
    imports_panel_.draw();
    exports_panel_.draw();
    symbols_panel_.draw();
    pe_headers_panel_.draw();
    pe_imports_panel_.draw();
    pe_exports_panel_.draw();
    log_panel_.draw();

    if (show_disassembly_panel_) {
        render_disassembly_panel();
    }
    if (show_call_graph_panel_) {
        render_call_graph_panel();
    }
    if (show_demo_window_)
        ImGui::ShowDemoWindow(&show_demo_window_);
}

void UiApp::render_main_menu() {
    if (!ImGui::BeginMainMenuBar())
        return;

    if (ImGui::BeginMenu("File")) {
        if (ImGui::MenuItem("Open...", "Ctrl+O")) {
            if (on_open_file_) { on_open_file_(); }
        }
        if (ImGui::MenuItem("Attach to Process...", "Ctrl+P")) {
            open_attach_process_modal();
        }
        if (ImGui::MenuItem("Refresh Process Memory Map", "F5", false, model_.is_live_process())) {
            auto res = model_.refresh_process_map();
            if (res) {
                sync_live_process_view(false);
                Log().info("Refreshed process memory map");
            } else {
                Log().error("Refresh failed: {}", res.error().message);
            }
        }
        if (ImGui::MenuItem("Detach from Process", nullptr, false, model_.is_live_process())) {
            model_.detach_process();
            on_file_loaded();
            Log().info("Detached from live process");
        }
        ImGui::Separator();
        if (ImGui::MenuItem("Open Debug Symbols...", nullptr, false, model_.image() != nullptr)) {
            if (on_open_debug_symbols_) { on_open_debug_symbols_(); }
        }
        if (ImGui::MenuItem("Save Patched As...",
                            nullptr,
                            false,
                            !model_.is_live_process() && model_.editable_image() != nullptr)) {
            if (on_save_patched_as_) { on_save_patched_as_(); }
        }
        if (ImGui::MenuItem("Commit Patches to Process",
                            nullptr,
                            false,
                            model_.is_live_process() && !model_.staged_live_patches().empty())) {
            auto res = model_.commit_patches_to_process(
                peelf::MemoryWriteOptions{.allow_protection_override = true});
            if (res) {
                Log().info("Committed {} staged patch range(s) to live process RAM", *res);
                refresh_disassembly();
            } else {
                Log().error("Commit to RAM failed: {}", res.error().message);
            }
        }
        if (ImGui::MenuItem("Discard Staged Patches",
                            nullptr,
                            false,
                            model_.is_live_process() && !model_.staged_live_patches().empty())) {
            model_.discard_staged_patches();
            refresh_disassembly();
            Log().info("Discarded staged live patches");
        }
        if (ImGui::MenuItem("Revert Committed RAM Patches",
                            nullptr,
                            false,
                            model_.is_live_process() && !model_.committed_live_patches().empty())) {
            auto res = model_.revert_committed_patches(
                peelf::MemoryWriteOptions{.allow_protection_override = true});
            if (res) {
                Log().info("Reverted {} committed patch range(s) in process RAM", *res);
                refresh_disassembly();
            } else {
                Log().error("Revert committed RAM patches failed: {}", res.error().message);
            }
        }
        ImGui::Separator();
        if (ImGui::MenuItem("Exit", "Alt+F4")) {
            // handled by Application
        }
        ImGui::EndMenu();
    }

    if (ImGui::BeginMenu("View")) {
        if (ImGui::MenuItem("Reset Layout")) {
            reset_dock_layout_ = true;
        }
        ImGui::Separator();
        ImGui::MenuItem("ImGui Demo", nullptr, &show_demo_window_);

        {
            bool v = file_panel_.visible();
            if (ImGui::MenuItem(file_panel_.name().c_str(), nullptr, &v))
                file_panel_.set_visible(v);
        }

        {
            bool v = memory_map_panel_.visible();
            if (ImGui::MenuItem(memory_map_panel_.name().c_str(), nullptr, &v))
                memory_map_panel_.set_visible(v);
        }

        {
            bool v = structure_panel_.visible();
            if (ImGui::MenuItem(structure_panel_.name().c_str(), nullptr, &v))
                structure_panel_.set_visible(v);
        }

        {
            bool v = details_panel_.visible();
            if (ImGui::MenuItem(details_panel_.name().c_str(), nullptr, &v))
                details_panel_.set_visible(v);
        }

        {
            bool v = sections_panel_.visible();
            if (ImGui::MenuItem(sections_panel_.name().c_str(), nullptr, &v))
                sections_panel_.set_visible(v);
        }

        {
            bool v = hex_panel_.visible();
            if (ImGui::MenuItem(hex_panel_.name().c_str(), nullptr, &v))
                hex_panel_.set_visible(v);
        }

        {
            bool v = patch_set_panel_.visible();
            if (ImGui::MenuItem(patch_set_panel_.name().c_str(), nullptr, &v))
                patch_set_panel_.set_visible(v);
        }

        {
            bool v = shellcode_panel_.visible();
            if (ImGui::MenuItem(shellcode_panel_.name().c_str(), nullptr, &v))
                shellcode_panel_.set_visible(v);
        }

        {
            bool v = imports_panel_.visible();
            if (ImGui::MenuItem(imports_panel_.name().c_str(), nullptr, &v))
                imports_panel_.set_visible(v);
        }

        {
            bool v = exports_panel_.visible();
            if (ImGui::MenuItem(exports_panel_.name().c_str(), nullptr, &v))
                exports_panel_.set_visible(v);
        }

        {
            bool v = symbols_panel_.visible();
            if (ImGui::MenuItem(symbols_panel_.name().c_str(), nullptr, &v))
                symbols_panel_.set_visible(v);
        }

        {
            bool v = pe_headers_panel_.visible();
            if (ImGui::MenuItem(pe_headers_panel_.name().c_str(), nullptr, &v))
                pe_headers_panel_.set_visible(v);
        }

        {
            bool v = pe_imports_panel_.visible();
            if (ImGui::MenuItem(pe_imports_panel_.name().c_str(), nullptr, &v))
                pe_imports_panel_.set_visible(v);
        }

        {
            bool v = pe_exports_panel_.visible();
            if (ImGui::MenuItem(pe_exports_panel_.name().c_str(), nullptr, &v))
                pe_exports_panel_.set_visible(v);
        }

        {
            ImGui::MenuItem("Disassembly", nullptr, &show_disassembly_panel_);
        }

        {
            ImGui::MenuItem("Call Graph", nullptr, &show_call_graph_panel_);
        }

        {
            bool v = log_panel_.visible();
            if (ImGui::MenuItem(log_panel_.name().c_str(), nullptr, &v))
                log_panel_.set_visible(v);
        }

        ImGui::EndMenu();
    }

    ImGui::EndMainMenuBar();
}

void UiApp::render_dockspace() {
    ImGuiViewport* viewport = ImGui::GetMainViewport();
    ImGui::SetNextWindowPos(viewport->WorkPos);
    ImGui::SetNextWindowSize(viewport->WorkSize);
    ImGui::SetNextWindowViewport(viewport->ID);

    ImGuiWindowFlags window_flags =
        ImGuiWindowFlags_NoTitleBar |
        ImGuiWindowFlags_NoCollapse |
        ImGuiWindowFlags_NoResize |
        ImGuiWindowFlags_NoMove |
        ImGuiWindowFlags_NoBringToFrontOnFocus |
        ImGuiWindowFlags_NoNavFocus |
        ImGuiWindowFlags_NoBackground;

    ImGui::PushStyleVar(ImGuiStyleVar_WindowRounding, 0.0f);
    ImGui::PushStyleVar(ImGuiStyleVar_WindowBorderSize, 0.0f);
    ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(0.0f, 0.0f));

    ImGui::Begin("MainDockSpaceHost", nullptr, window_flags);
    ImGui::PopStyleVar(3);

    const ImGuiID dockspace_id = ImGui::GetID("MainDockSpace");
    const ImGuiDockNodeFlags dock_flags = ImGuiDockNodeFlags_None;
    if (reset_dock_layout_ || ImGui::DockBuilderGetNode(dockspace_id) == nullptr) {
        build_default_dock_layout(dockspace_id, viewport->WorkSize);
        reset_dock_layout_ = false;
    }
    ImGui::DockSpace(dockspace_id, ImVec2(0.0f, 0.0f), dock_flags);

    ImGui::End();
}

void UiApp::open_attach_process_modal() {
    attach_error_message_.clear();
    refresh_process_list();
    open_attach_modal_next_frame_ = true;
}

void UiApp::refresh_process_list() {
    auto listed = model_.list_processes();
    if (!listed) {
        attach_error_message_ = "Failed to enumerate processes: " + listed.error().message;
        cached_process_list_.clear();
        return;
    }
    cached_process_list_ = std::move(*listed);
}

void UiApp::render_attach_process_modal() {
    if (open_attach_modal_next_frame_) {
        ImGui::OpenPopup("Attach to Process");
        open_attach_modal_next_frame_ = false;
    }

    ImGui::SetNextWindowSize(ImVec2(860.0f, 540.0f), ImGuiCond_FirstUseEver);
    bool modal_open = true;
    if (!ImGui::BeginPopupModal("Attach to Process", &modal_open)) {
        return;
    }

    auto try_attach_pid = [this](peelf::ProcessId pid) {
        auto attached = model_.attach_process(pid);
        if (!attached) {
            attach_error_message_ = std::format("Attach to PID {} failed: {}", pid, attached.error().message);
            Log().error("{}", attach_error_message_);
            return;
        }
        attach_error_message_.clear();
        on_process_attached();
        ImGui::CloseCurrentPopup();
    };

    ImGui::SetNextItemWidth(320.0f);
    ImGui::InputTextWithHint("##ProcSearch",
                             "Filter by PID, name, path, or command line...",
                             process_filter_buf_,
                             sizeof(process_filter_buf_));
    ImGui::SameLine();
    if (ImGui::Button("Refresh")) {
        refresh_process_list();
    }
    ImGui::SameLine();
    if (ImGui::Button("Attach Self")) {
        try_attach_pid(peelf::current_process_id());
    }
    ImGui::SameLine();
    ImGui::Checkbox("Accessible only", &process_accessible_only_);

    ImGui::SetNextItemWidth(140.0f);
    ImGui::InputTextWithHint("##ManualPid", "PID...", manual_pid_buf_, sizeof(manual_pid_buf_), ImGuiInputTextFlags_CharsDecimal);
    ImGui::SameLine();
    if (ImGui::Button("Attach PID")) {
        char* end = nullptr;
        const unsigned long long parsed = std::strtoull(manual_pid_buf_, &end, 10);
        if (end != manual_pid_buf_ && parsed > 0 &&
            parsed <= static_cast<unsigned long long>(std::numeric_limits<peelf::ProcessId>::max())) {
            try_attach_pid(static_cast<peelf::ProcessId>(parsed));
        } else {
            attach_error_message_ = "Enter a valid positive numeric PID.";
        }
    }
    ImGui::SameLine();
    ImGui::TextDisabled("(%zu processes enumerated)", cached_process_list_.size());

    if (!attach_error_message_.empty()) {
        ImGui::TextColored(ImVec4(1.0f, 0.45f, 0.45f, 1.0f), "%s", attach_error_message_.c_str());
    }

    ImGui::Separator();

    const std::string_view filter(process_filter_buf_);
    const float footer_height = ImGui::GetFrameHeightWithSpacing() + 8.0f;
    if (ImGui::BeginTable("AttachProcessTable",
                          6,
                          ImGuiTableFlags_Borders |
                              ImGuiTableFlags_RowBg |
                              ImGuiTableFlags_Resizable |
                              ImGuiTableFlags_ScrollY,
                          ImVec2(0.0f, -footer_height))) {
        ImGui::TableSetupColumn("PID", ImGuiTableColumnFlags_WidthFixed, 76.0f);
        ImGui::TableSetupColumn("Name", ImGuiTableColumnFlags_WidthFixed, 165.0f);
        ImGui::TableSetupColumn("Arch", ImGuiTableColumnFlags_WidthFixed, 72.0f);
        ImGui::TableSetupColumn("User", ImGuiTableColumnFlags_WidthFixed, 100.0f);
        ImGui::TableSetupColumn("Access", ImGuiTableColumnFlags_WidthFixed, 68.0f);
        ImGui::TableSetupColumn("Executable / Command Line", ImGuiTableColumnFlags_WidthStretch);
        ImGui::TableHeadersRow();

        for (const peelf::ProcessInfo& proc : cached_process_list_) {
            const bool is_accessible = proc.access == peelf::ProcessAccessStatus::Accessible ||
                                       proc.access == peelf::ProcessAccessStatus::ReadOnly;
            if (process_accessible_only_ && !is_accessible) {
                continue;
            }
            const std::string exe_path_str = proc.executable_path.string();
            std::array<char, 32> pid_str{};
            std::snprintf(pid_str.data(), pid_str.size(), "%" PRIu32, proc.pid);
            if (!filter.empty() &&
                !icontains_filter(pid_str.data(), filter) &&
                !icontains_filter(proc.name, filter) &&
                !icontains_filter(exe_path_str, filter) &&
                !icontains_filter(proc.command_line, filter)) {
                continue;
            }

            const bool is_sel = selected_attach_pid_ && *selected_attach_pid_ == proc.pid;
            ImGui::TableNextRow();
            ImGui::TableNextColumn();
            ImGui::PushID(static_cast<int>(proc.pid & 0x7FFFFFFFu));
            if (ImGui::Selectable(pid_str.data(),
                                  is_sel,
                                  ImGuiSelectableFlags_SpanAllColumns |
                                      ImGuiSelectableFlags_AllowDoubleClick)) {
                selected_attach_pid_ = proc.pid;
                if (ImGui::IsMouseDoubleClicked(ImGuiMouseButton_Left)) {
                    try_attach_pid(proc.pid);
                }
            }
            ImGui::PopID();

            ImGui::TableNextColumn();
            ImGui::TextUnformatted(proc.name.empty() ? "<unknown>" : proc.name.c_str());

            ImGui::TableNextColumn();
            const std::string_view arch = peelf::to_string(proc.architecture);
            ImGui::TextUnformatted(arch.data(), arch.data() + arch.size());

            ImGui::TableNextColumn();
            ImGui::TextUnformatted(proc.user.empty() ? "-" : proc.user.c_str());

            ImGui::TableNextColumn();
            const std::string_view access_label = peelf::to_string(proc.access);
            ImGui::TextColored(is_accessible ? ImVec4(0.40f, 0.90f, 0.55f, 1.0f)
                                             : ImVec4(0.70f, 0.55f, 0.55f, 1.0f),
                               "%.*s",
                               static_cast<int>(access_label.size()),
                               access_label.data());

            ImGui::TableNextColumn();
            const std::string& detail = !exe_path_str.empty() ? exe_path_str : proc.command_line;
            if (!detail.empty()) {
                ImGui::TextUnformatted(detail.c_str());
            } else {
                ImGui::TextDisabled("-");
            }
        }

        ImGui::EndTable();
    }

    ImGui::BeginDisabled(!selected_attach_pid_.has_value());
    if (ImGui::Button("Attach", ImVec2(110.0f, 0.0f)) && selected_attach_pid_) {
        try_attach_pid(*selected_attach_pid_);
    }
    ImGui::EndDisabled();
    ImGui::SameLine();
    if (ImGui::Button("Cancel", ImVec2(110.0f, 0.0f))) {
        ImGui::CloseCurrentPopup();
    }

    ImGui::EndPopup();
}

void UiApp::load_call_graph_sample(CallGraphSample sample) {
    pending_call_graph_request_.reset();
    if (sample == CallGraphSample::LoadedImage) {
        const peelf::IBinaryImage* image = model_.image();
        if (image == nullptr) {
            call_graph_status_ = "No image loaded. Open a PE/ELF file or select a live module.";
            return;
        }
        load_call_graph_from_graph(build_entry_call_graph(*image, model_.symbol_index()), graph_bmp_name(sample));
        call_graph_sample_ = sample;
        return;
    }

    call_graph_status_ = "Sample bitmap rendering is disabled while the Vulkan texture path is isolated.";
    call_graph_sample_ = sample;
}

void UiApp::queue_call_graph_sample(CallGraphSample sample) {
    pending_call_graph_request_ = PendingCallGraphRequest{
        .sample = sample,
        .delay_frames = 1,
    };
    call_graph_sample_ = sample;
    call_graph_status_ = "Queued call graph render";
}

void UiApp::process_deferred_gpu_work() {
    if (pending_call_graph_request_) {
        if (pending_call_graph_request_->delay_frames > 0) {
            --pending_call_graph_request_->delay_frames;
        } else {
            const CallGraphSample sample = pending_call_graph_request_->sample;
            pending_call_graph_request_.reset();
            load_call_graph_sample(sample);
            return;
        }
    }

    if (pending_call_graph_root_ && pending_call_graph_delay_frames_ > 0) {
        --pending_call_graph_delay_frames_;
    } else if (pending_call_graph_root_) {
        const peelf::IBinaryImage* img = model_.image();
        const SymbolRecord root = *pending_call_graph_root_;
        pending_call_graph_root_.reset();
        pending_call_graph_delay_frames_ = 0;
        if (img != nullptr) {
            const GraphByteReader reader = [this](std::uint64_t offset, std::size_t length)
                -> std::vector<std::uint8_t> {
                auto sample = model_.read_window_sample(offset, length);
                if (!sample || sample->bytes.empty()) {
                    return {};
                }
                std::size_t readable_prefix = 0;
                while (readable_prefix < sample->valid.size() && sample->valid[readable_prefix] != 0) {
                    ++readable_prefix;
                }
                sample->bytes.resize(readable_prefix);
                return std::move(sample->bytes);
            };
            load_call_graph_from_graph(
                build_symbol_fanout_call_graph(*img,
                                               reader,
                                               model_.symbol_index(),
                                               root),
                "loaded_symbol_fanout_call_graph.bmp");
            call_graph_status_ = "Loaded fan-out from " + root.name;
        }
    }
}

void UiApp::load_call_graph_from_graph(CallGraph graph, const std::filesystem::path& output_name) {
    const std::filesystem::path plain_path = std::filesystem::temp_directory_path() / (output_name.string() + ".plain");
    const DefaultProcessRunner runner;
    const GraphRenderResult render_result =
        render_graph_with_graphviz(graph, plain_path, GraphRenderFormat::Plain, runner);
    if (!render_result.success) {
        call_graph_status_ = "Graphviz failed to lay out loaded-image graph: " + render_result.diagnostic;
        return;
    }

    const std::optional<std::string> plain_text = read_text_file(plain_path);
    if (!plain_text) {
        call_graph_status_ = "Failed to load rendered graph layout: " + plain_path.string();
        return;
    }

    current_call_graph_layout_ = parse_graphviz_plain_layout(*plain_text);
    if (!current_call_graph_layout_) {
        call_graph_status_ = "Graphviz produced an unreadable graph layout: " + plain_path.string();
        return;
    }

    if (call_graph_texture_) {
        vulkan_.destroy_texture(*call_graph_texture_);
        call_graph_texture_.reset();
    }

    loaded_call_graph_bmp_ = plain_path;
    current_call_graph_ = std::move(graph);
    call_graph_status_ = "Loaded graph layout from current image";
}

const CallGraphNode* UiApp::hit_test_call_graph_node(const ImVec2& image_pos,
                                                     float graph_scale,
                                                     double graph_min_x,
                                                     double graph_max_y,
                                                     const ImVec2& mouse_pos) const {
    if (!current_call_graph_ || !current_call_graph_layout_ ||
        current_call_graph_layout_->width <= 0.0 || current_call_graph_layout_->height <= 0.0 ||
        graph_scale <= 0.0f) {
        return nullptr;
    }
    const double graph_x = graph_min_x + static_cast<double>(mouse_pos.x - image_pos.x) / graph_scale;
    const double graph_y = graph_max_y - static_cast<double>(mouse_pos.y - image_pos.y) / graph_scale;

    for (const GraphLayoutNode& layout_node : current_call_graph_layout_->nodes) {
        const double left = layout_node.center_x - layout_node.width * 0.5;
        const double right = layout_node.center_x + layout_node.width * 0.5;
        const double bottom = layout_node.center_y - layout_node.height * 0.5;
        const double top = layout_node.center_y + layout_node.height * 0.5;
        if (graph_x >= left && graph_x <= right && graph_y >= bottom && graph_y <= top) {
            const auto it = std::ranges::find_if(current_call_graph_->nodes, [&](const CallGraphNode& node) {
                return node.id == layout_node.node_id;
            });
            return it == current_call_graph_->nodes.end() ? nullptr : &*it;
        }
    }
    return nullptr;
}

void UiApp::activate_call_graph_node(const CallGraphNode& node) {
    const peelf::IBinaryImage* img = model_.image();
    if (img == nullptr) {
        return;
    }

    current_selection_ = selection_from_call_graph_node(node, *img);
    std::optional<std::uint64_t> nav_offset = current_selection_.file_offset;
    if (current_selection_.virtual_address) {
        if (const auto model_off = model_.virtual_address_to_offset(*current_selection_.virtual_address)) {
            nav_offset = model_off;
            current_selection_.file_offset = model_off;
        }
    }

    if (nav_offset) {
        const std::uint64_t size = current_selection_.size != 0 ? current_selection_.size : 1u;
        hex_panel_.navigate_to_range(clamp_to_size_t(*nav_offset), clamp_to_size_t(size));
        const std::uint64_t display_address = current_selection_.virtual_address
            ? *current_selection_.virtual_address
            : *nav_offset;
        disassemble_at_offset(*nav_offset, display_address);
    }
    last_navigation_selection_ = current_selection_;

    const SymbolIndex& sym_idx = model_.symbol_index();
    const SymbolRecord* record = nullptr;
    if (node.symbol && !node.symbol->name.empty()) {
        record = sym_idx.find_by_name(node.symbol->name);
    }
    if (!node.label.empty()) {
        if (record == nullptr) {
            record = sym_idx.find_by_name(node.label);
        }
    }
    if (record == nullptr && node.bytes.start.virtual_address) {
        record = sym_idx.find_containing_address(*node.bytes.start.virtual_address);
    }
    if (record != nullptr && record->virtual_address) {
        SymbolRecord resolved = *record;
        if (!resolved.file_offset) {
            resolved.file_offset = model_.virtual_address_to_offset(*resolved.virtual_address);
        }
        if (resolved.file_offset) {
            pending_call_graph_root_ = std::move(resolved);
            pending_call_graph_delay_frames_ = 1;
            call_graph_status_ = "Queued fan-out from " + record->name;
        }
    }
}

void UiApp::render_call_graph_panel() {
    ImGui::SetNextWindowSize(ImVec2(900.0f, 420.0f), ImGuiCond_FirstUseEver);
    if (!ImGui::Begin("Call Graph", &show_call_graph_panel_)) {
        ImGui::End();
        return;
    }

    if (ImGui::Button("Loaded Image")) {
        queue_call_graph_sample(CallGraphSample::LoadedImage);
    }
    ImGui::SameLine();
    if (ImGui::Button("PE x64 sample")) {
        queue_call_graph_sample(CallGraphSample::PeStartup);
    }
    ImGui::SameLine();
    if (ImGui::Button("Linux ELF sample")) {
        queue_call_graph_sample(CallGraphSample::ElfStartup);
    }
    ImGui::SameLine();
    if (ImGui::Button("Reload")) {
        queue_call_graph_sample(call_graph_sample_);
    }

    if (!call_graph_status_.empty()) {
        ImGui::TextUnformatted(call_graph_status_.c_str());
    }

    const ImVec2 available = ImGui::GetContentRegionAvail();
    const ImVec2 canvas_size(std::max(available.x, 64.0f), std::max(available.y, 64.0f));
    const ImVec2 canvas_pos = ImGui::GetCursorScreenPos();
    ImDrawList* draw_list = ImGui::GetWindowDrawList();
    draw_list->AddRectFilled(canvas_pos,
                             ImVec2(canvas_pos.x + canvas_size.x, canvas_pos.y + canvas_size.y),
                             IM_COL32(255, 255, 255, 255));

    if (current_call_graph_ && current_call_graph_layout_) {
        const GraphLayoutBounds bounds = graph_layout_bounds(*current_call_graph_layout_);
        const float graph_width = static_cast<float>(std::max(1.0, bounds.max_x - bounds.min_x));
        const float graph_height = static_cast<float>(std::max(1.0, bounds.max_y - bounds.min_y));
        constexpr float kGraphPadding = 32.0f;
        const ImVec2 padded_canvas_size(std::max(1.0f, canvas_size.x - kGraphPadding * 2.0f),
                                        std::max(1.0f, canvas_size.y - kGraphPadding * 2.0f));
        const float scale = std::min(padded_canvas_size.x / graph_width, padded_canvas_size.y / graph_height);
        const ImVec2 draw_size(std::max(1.0f, graph_width * scale), std::max(1.0f, graph_height * scale));
        const ImVec2 graph_pos(canvas_pos.x + (canvas_size.x - draw_size.x) * 0.5f,
                               canvas_pos.y + (canvas_size.y - draw_size.y) * 0.5f);

        const auto to_screen = [&](double graph_x, double graph_y) {
            return ImVec2(graph_pos.x + static_cast<float>(graph_x - bounds.min_x) * scale,
                          graph_pos.y + static_cast<float>(bounds.max_y - graph_y) * scale);
        };
        const auto find_layout = [&](std::string_view node_id) -> const GraphLayoutNode* {
            const auto it = std::ranges::find_if(current_call_graph_layout_->nodes, [&](const GraphLayoutNode& node) {
                return node.node_id == node_id;
            });
            return it == current_call_graph_layout_->nodes.end() ? nullptr : &*it;
        };

        for (const CallGraphEdge& edge : current_call_graph_->edges) {
            const GraphLayoutNode* from = find_layout(edge.from_node_id);
            const GraphLayoutNode* to = find_layout(edge.to_node_id);
            if (from == nullptr || to == nullptr) {
                continue;
            }
            draw_list->AddLine(to_screen(from->center_x, from->center_y),
                               to_screen(to->center_x, to->center_y),
                               IM_COL32(80, 130, 180, 255),
                               2.0f);
        }

        for (const GraphLayoutNode& layout_node : current_call_graph_layout_->nodes) {
            const auto graph_node = std::ranges::find_if(current_call_graph_->nodes, [&](const CallGraphNode& node) {
                return node.id == layout_node.node_id;
            });
            const std::string label = graph_node == current_call_graph_->nodes.end()
                                          ? layout_node.node_id
                                          : call_graph_node_display_label(*graph_node);
            bool selected = false;
            const peelf::IBinaryImage* img = model_.image();
            if (graph_node != current_call_graph_->nodes.end() && img != nullptr) {
                selected = same_selection(current_selection_, selection_from_call_graph_node(*graph_node, *img));
            }
            const ImVec2 top_left = to_screen(layout_node.center_x - layout_node.width * 0.5,
                                              layout_node.center_y + layout_node.height * 0.5);
            const ImVec2 bottom_right = to_screen(layout_node.center_x + layout_node.width * 0.5,
                                                  layout_node.center_y - layout_node.height * 0.5);
            draw_list->AddRectFilled(top_left,
                                     bottom_right,
                                     selected ? IM_COL32(232, 244, 255, 255) : IM_COL32(248, 248, 248, 255),
                                     4.0f);
            draw_list->AddRect(top_left,
                               bottom_right,
                               selected ? IM_COL32(26, 98, 170, 255) : IM_COL32(50, 50, 50, 255),
                               4.0f,
                               0,
                               selected ? 3.0f : 2.0f);
            const ImVec2 text_size = ImGui::CalcTextSize(label.c_str());
            const ImVec2 text_pos(top_left.x + std::max(4.0f, (bottom_right.x - top_left.x - text_size.x) * 0.5f),
                                  top_left.y + std::max(4.0f, (bottom_right.y - top_left.y - text_size.y) * 0.5f));
            draw_list->AddText(text_pos, IM_COL32(35, 35, 35, 255), label.c_str());
        }

        ImGui::SetCursorScreenPos(graph_pos);
        ImGui::InvisibleButton("CallGraphVectorHitTarget", draw_size);
        if (ImGui::IsItemClicked(ImGuiMouseButton_Left)) {
            if (const CallGraphNode* node =
                    hit_test_call_graph_node(graph_pos, scale, bounds.min_x, bounds.max_y, ImGui::GetIO().MousePos)) {
                activate_call_graph_node(*node);
            }
        }
    } else if (call_graph_texture_) {
        const float image_width = static_cast<float>(call_graph_texture_->width);
        const float image_height = static_cast<float>(call_graph_texture_->height);
        const float scale = std::min(canvas_size.x / image_width, canvas_size.y / image_height);
        const ImVec2 draw_size(std::max(1.0f, image_width * scale), std::max(1.0f, image_height * scale));
        const ImVec2 image_pos(canvas_pos.x + (canvas_size.x - draw_size.x) * 0.5f,
                               canvas_pos.y + (canvas_size.y - draw_size.y) * 0.5f);
        ImTextureID texture_id = reinterpret_cast<ImTextureID>(call_graph_texture_->descriptor_set);
        draw_list->AddImage(texture_id,
                            image_pos,
                            ImVec2(image_pos.x + draw_size.x, image_pos.y + draw_size.y));
        ImGui::SetCursorScreenPos(image_pos);
        ImGui::InvisibleButton("CallGraphImageHitTarget", draw_size);
        if (ImGui::IsItemClicked(ImGuiMouseButton_Left)) {
            const float image_scale = current_call_graph_layout_ && current_call_graph_layout_->width > 0.0
                                          ? draw_size.x / static_cast<float>(current_call_graph_layout_->width)
                                          : 1.0f;
            if (const CallGraphNode* node = hit_test_call_graph_node(image_pos,
                                                                     image_scale,
                                                                     0.0,
                                                                     current_call_graph_layout_
                                                                         ? current_call_graph_layout_->height
                                                                         : 0.0,
                                                                     ImGui::GetIO().MousePos)) {
                activate_call_graph_node(*node);
            }
        }
    } else {
        const char* message = "No graph rendered yet. Click Loaded Image or Reload.";
        const ImVec2 text_size = ImGui::CalcTextSize(message);
        draw_list->AddText(ImVec2(canvas_pos.x + (canvas_size.x - text_size.x) * 0.5f,
                                  canvas_pos.y + (canvas_size.y - text_size.y) * 0.5f),
                           IM_COL32(80, 80, 80, 255),
                           message);
    }

    if (!call_graph_texture_) {
        ImGui::Dummy(canvas_size);
    } else {
        ImGui::SetCursorScreenPos(ImVec2(canvas_pos.x, canvas_pos.y + canvas_size.y));
    }
    ImGui::End();
}

void UiApp::build_default_dock_layout(ImGuiID dockspace_id, const ImVec2& dockspace_size) {
    ImGui::DockBuilderRemoveNode(dockspace_id);
    ImGui::DockBuilderAddNode(dockspace_id, ImGuiDockNodeFlags_DockSpace);
    ImGui::DockBuilderSetNodeSize(dockspace_id, dockspace_size);

    ImGuiID main_id = dockspace_id;
    const ImGuiID left_id = ImGui::DockBuilderSplitNode(main_id, ImGuiDir_Left, 0.22f, nullptr, &main_id);
    const ImGuiID right_id = ImGui::DockBuilderSplitNode(main_id, ImGuiDir_Right, 0.24f, nullptr, &main_id);
    const ImGuiID bottom_id = ImGui::DockBuilderSplitNode(main_id, ImGuiDir_Down, 0.22f, nullptr, &main_id);
    const ImGuiID center_bottom_id = ImGui::DockBuilderSplitNode(main_id, ImGuiDir_Down, 0.42f, nullptr, &main_id);

    ImGui::DockBuilderDockWindow(structure_panel_.name().c_str(), left_id);
    ImGui::DockBuilderDockWindow(memory_map_panel_.name().c_str(), left_id);
    ImGui::DockBuilderDockWindow(file_panel_.name().c_str(), left_id);
    ImGui::DockBuilderDockWindow(sections_panel_.name().c_str(), left_id);
    ImGui::DockBuilderDockWindow(symbols_panel_.name().c_str(), left_id);
    ImGui::DockBuilderDockWindow(patch_set_panel_.name().c_str(), left_id);

    ImGui::DockBuilderDockWindow(details_panel_.name().c_str(), right_id);
    ImGui::DockBuilderDockWindow(imports_panel_.name().c_str(), right_id);
    ImGui::DockBuilderDockWindow(exports_panel_.name().c_str(), right_id);
    ImGui::DockBuilderDockWindow(pe_headers_panel_.name().c_str(), right_id);
    ImGui::DockBuilderDockWindow(pe_imports_panel_.name().c_str(), right_id);
    ImGui::DockBuilderDockWindow(pe_exports_panel_.name().c_str(), right_id);

    ImGui::DockBuilderDockWindow(hex_panel_.name().c_str(), main_id);
    ImGui::DockBuilderDockWindow(shellcode_panel_.name().c_str(), main_id);
    ImGui::DockBuilderDockWindow("Disassembly", center_bottom_id);
    ImGui::DockBuilderDockWindow(log_panel_.name().c_str(), bottom_id);

    ImGui::DockBuilderFinish(dockspace_id);
}

    void UiApp::render_disassembly_panel() {
    ImGui::Begin("Disassembly");

    if (!file_loaded_ || !disasm_.is_initialized()) {
        ImGui::TextDisabled("No file or live process loaded, or disassembler not initialized.");
        ImGui::End();
        return;
    }

    if (!disasm_status_.empty()) {
        ImGui::TextColored(ImVec4(1.0f, 0.72f, 0.30f, 1.0f), "%s", disasm_status_.c_str());
    }

    // Table view with live symbol resolution and patch-state tinting
    if (ImGui::BeginTable("DisasmTable", 5,
                          ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg |
                          ImGuiTableFlags_ScrollY | ImGuiTableFlags_Resizable)) {
        ImGui::TableSetupColumn("Address", ImGuiTableColumnFlags_WidthFixed, 132.0f);
        ImGui::TableSetupColumn("Symbol", ImGuiTableColumnFlags_WidthFixed, 150.0f);
        ImGui::TableSetupColumn("Bytes", ImGuiTableColumnFlags_WidthFixed, 180.0f);
        ImGui::TableSetupColumn("Mnemonic", ImGuiTableColumnFlags_WidthFixed, 84.0f);
        ImGui::TableSetupColumn("Operands", ImGuiTableColumnFlags_WidthStretch);
        ImGui::TableHeadersRow();

        const SymbolIndex& sym_idx = model_.symbol_index();
        for (const auto &inst: current_instructions_) {
            ImGui::TableNextRow();

            // Address
            ImGui::TableNextColumn();
            ImGui::Text("0x%016" PRIX64, inst.address);

            // Symbol label (exact match or containing symbol + delta)
            ImGui::TableNextColumn();
            if (const SymbolRecord* exact = sym_idx.find_exact_address(inst.address)) {
                ImGui::TextColored(ImVec4(0.55f, 0.88f, 1.0f, 1.0f), "%s:", exact->name.c_str());
            } else if (const SymbolRecord* containing = sym_idx.find_containing_address(inst.address)) {
                if (containing->virtual_address && inst.address > *containing->virtual_address) {
                    ImGui::TextDisabled("%s+0x%" PRIX64,
                                        containing->name.c_str(),
                                        inst.address - *containing->virtual_address);
                } else {
                    ImGui::TextDisabled("%s", containing->name.c_str());
                }
            } else {
                ImGui::TextDisabled("-");
            }

            // Bytes (highlight if any instruction byte is staged or committed)
            ImGui::TableNextColumn();
            BytePatchState inst_patch_state = BytePatchState::Unchanged;
            if (const auto base_off = model_.virtual_address_to_offset(inst.address)) {
                for (std::size_t bi = 0; bi < inst.bytes.size(); ++bi) {
                    const BytePatchState st = model_.byte_patch_state_at_offset(*base_off + bi);
                    if (st == BytePatchState::Staged) {
                        inst_patch_state = BytePatchState::Staged;
                        break;
                    }
                    if (st == BytePatchState::Committed) {
                        inst_patch_state = BytePatchState::Committed;
                    }
                }
            }
            std::string bytes_str;
            for (std::uint8_t b: inst.bytes) {
                char buf[4];
                std::snprintf(buf, sizeof(buf), "%02X ", b);
                bytes_str += buf;
            }
            if (inst_patch_state == BytePatchState::Staged) {
                ImGui::TextColored(ImVec4(1.0f, 0.78f, 0.25f, 1.0f), "%s", bytes_str.c_str());
            } else if (inst_patch_state == BytePatchState::Committed) {
                ImGui::TextColored(ImVec4(0.35f, 0.92f, 0.55f, 1.0f), "%s", bytes_str.c_str());
            } else {
                ImGui::TextDisabled("%s", bytes_str.c_str());
            }

            // Mnemonic (color-coded)
            ImGui::TableNextColumn();
            ImVec4 color = get_mnemonic_color(inst.mnemonic);
            ImGui::TextColored(color, "%s", inst.mnemonic.c_str());

            // Operands
            ImGui::TableNextColumn();
            ImGui::Text("%s", inst.operands.c_str());
        }

        ImGui::EndTable();
                          }

    ImGui::End();
}

    void UiApp::sync_live_process_view(bool navigate_to_entry) {
        if (!model_.is_live_process() || model_.process_session() == nullptr) {
            return;
        }

        const peelf::IProcessSession* sess = model_.process_session();
        structure_tree_ = build_live_process_structure_tree(
            sess->info(),
            model_.process_modules(),
            model_.memory_regions(),
            model_.image(),
            model_.active_module_index());

        pending_call_graph_root_.reset();
        pending_call_graph_delay_frames_ = 0;
        pending_call_graph_request_.reset();
        if (call_graph_texture_) {
            vulkan_.destroy_texture(*call_graph_texture_);
            call_graph_texture_.reset();
        }

        const peelf::Architecture target_arch = model_.architecture() != peelf::Architecture::Unknown
            ? model_.architecture()
            : sess->info().architecture;
        if (const std::optional<viewer::Architecture> arch = disassembler_architecture(target_arch)) {
            file_loaded_ = disasm_.init(*arch, disassembler_endianness(model_.endianness()));
        } else {
            file_loaded_ = false;
        }

        if (const PeModel* pe = model_.pe()) {
            pe_model_ = *pe;
        } else {
            pe_model_ = {};
        }

        if (navigate_to_entry) {
            current_instructions_.clear();
            disasm_status_.clear();
            if (structure_tree_) {
                current_selection_ = structure_tree_->selection;
            }
            const peelf::IBinaryImage* img = model_.image();
            if (img != nullptr && img->entry_point() != 0) {
                if (const auto entry_off = model_.virtual_address_to_offset(img->entry_point())) {
                    hex_panel_.navigate_to_range(clamp_to_size_t(*entry_off), 1);
                    disassemble_at_offset(*entry_off, img->entry_point());
                } else {
                    hex_panel_.navigate_to_range(0, 1);
                    disassemble_at_offset(0, model_.view_base_address());
                }
            } else if (model_.view_size() > 0) {
                hex_panel_.navigate_to_range(0, 1);
                disassemble_at_offset(0, model_.view_base_address());
            }
            last_navigation_selection_ = current_selection_;
            call_graph_sample_ = CallGraphSample::LoadedImage;
            call_graph_status_ = "Attached to live module. Click Loaded Image or Reload to render the call graph.";
        }
    }

    void UiApp::on_process_attached() {
        if (!model_.is_live_process() || model_.process_session() == nullptr) {
            return;
        }
        sync_live_process_view(true);
        Log().info("Attached to PID {} ({}): {} regions, {} modules, {} symbols",
                   model_.process_session()->pid(),
                   model_.process_session()->info().name,
                   model_.memory_regions().size(),
                   model_.process_modules().size(),
                   model_.symbol_index().size());
    }

    // Called after a file (PE or ELF) is loaded into the model, or after detaching.
    void UiApp::on_file_loaded() {
        if (model_.is_live_process()) {
            on_process_attached();
            return;
        }

        const peelf::IBinaryImage* img = model_.image();
        if (!img) {
            file_loaded_ = false;
            structure_tree_.reset();
            current_selection_ = {};
            last_navigation_selection_.reset();
            last_disasm_offset_.reset();
            current_instructions_.clear();
            disasm_status_.clear();
            pending_call_graph_root_.reset();
            pending_call_graph_delay_frames_ = 0;
            pending_call_graph_request_.reset();
            return;
        }

        structure_tree_ = build_structure_tree(*img);
        pending_call_graph_root_.reset();
        pending_call_graph_delay_frames_ = 0;
        pending_call_graph_request_.reset();
        if (const std::optional<std::filesystem::path> pdb = find_local_codeview_pdb(*img, model_.file_info().path)) {
            load_debug_symbols(*pdb);
        } else if (!img->pe_debug_directories().empty()) {
            for (const peelf::PeDebugDirectory& debug : img->pe_debug_directories()) {
                if (!debug.codeview_pdb_path.empty()) {
                    Log().info("CodeView references PDB '{}'; use File > Open Debug Symbols... if it is elsewhere",
                               debug.codeview_pdb_path);
                    break;
                }
            }
        }
        current_selection_ = structure_tree_->selection;
        last_navigation_selection_.reset();
        Log().info("Loaded {} symbol records", model_.symbol_index().size());

        // Map the unified architecture onto the disassembler's enum.
        const std::optional<viewer::Architecture> arch = disassembler_architecture(img->architecture());
        if (!arch) {
            Log().error(std::string("Disassembly is not supported for architecture: ") +
                        std::string(peelf::to_string(img->architecture())));
            file_loaded_ = false;
            current_instructions_.clear();
            return;
        }

        if (!disasm_.init(*arch, disassembler_endianness(img->endianness()))) {
            Log().error(std::string("Failed to initialize disassembler: ") + disasm_.get_error());
            file_loaded_ = false;
            return;
        }
        file_loaded_ = true;
        current_instructions_.clear();
        disasm_status_.clear();

        if (const auto entry_offset = img->virtual_address_to_file_offset(img->entry_point())) {
            hex_panel_.navigate_to_range(clamp_to_size_t(*entry_offset), 1);
            last_navigation_selection_ = current_selection_;
        }

        if (const PeModel* pe = model_.pe()) {
            pe_model_ = *pe;
            disassemble_entry_point(4096);
            if (const auto entry_offset = img->virtual_address_to_file_offset(img->entry_point())) {
                last_disasm_offset_ = *entry_offset;
                last_disasm_address_ = img->entry_point();
            }
        } else if (const auto entry_offset = img->virtual_address_to_file_offset(img->entry_point())) {
            disassemble_at_offset(*entry_offset, img->entry_point());
        }

        call_graph_sample_ = CallGraphSample::LoadedImage;
        call_graph_status_ = "Loaded image. Use Loaded Image or Reload to render the call graph.";
        if (call_graph_texture_) {
            vulkan_.destroy_texture(*call_graph_texture_);
            call_graph_texture_.reset();
        }
    }

    void UiApp::load_debug_symbols(const std::filesystem::path& path) {
        const peelf::IBinaryImage* img = model_.image();
        if (img == nullptr) {
            Log().warn("Cannot load debug symbols without a loaded image");
            return;
        }

        DebugSymbolLoadResult result = load_pdb_debug_symbols(path, *img);
        if (result.status != DebugSymbolLoadStatus::Loaded) {
            Log().warn("Debug symbols not loaded ({}): {}",
                       to_string(result.status),
                       result.diagnostic);
            return;
        }

        model_.add_debug_symbols(std::span<const DebugSymbol>(result.symbols.data(), result.symbols.size()));
        Log().info("Loaded {} debug symbols from {}; symbol index now has {} records",
                   result.symbols.size(),
                   path.string(),
                   model_.symbol_index().size());

        call_graph_status_ = "Debug symbols loaded. Use Reload to rebuild the call graph.";
        pending_call_graph_request_.reset();
        pending_call_graph_root_.reset();
        pending_call_graph_delay_frames_ = 0;
        if (call_graph_texture_) {
            vulkan_.destroy_texture(*call_graph_texture_);
            call_graph_texture_.reset();
        }
    }


    void UiApp::apply_structure_selection_navigation() {
        if (current_selection_.kind == SelectionKind::None ||
            current_selection_.kind == SelectionKind::Group ||
            current_selection_.kind == SelectionKind::Process) {
            return;
        }
        if (last_navigation_selection_ &&
            same_selection(*last_navigation_selection_, current_selection_)) {
            return;
        }

        if (current_selection_.kind == SelectionKind::ProcessModule && model_.is_live_process()) {
            const auto mod_idx = static_cast<std::size_t>(current_selection_.object_index);
            if (model_.active_module_index() != mod_idx && mod_idx < model_.process_modules().size()) {
                const ViewerSelection saved_sel = current_selection_;
                if (model_.select_process_module(mod_idx)) {
                    sync_live_process_view(true);
                    current_selection_ = saved_sel;
                }
            }
            last_navigation_selection_ = current_selection_;
            return;
        }

        if (current_selection_.kind == SelectionKind::MemoryRegion && model_.is_live_process()) {
            const auto reg_idx = static_cast<std::size_t>(current_selection_.object_index);
            if (reg_idx < model_.memory_regions().size()) {
                const peelf::MemoryRegion reg_copy = model_.memory_regions()[reg_idx];
                const ViewerSelection saved_sel = current_selection_;
                if (model_.select_memory_region(reg_idx, true)) {
                    sync_live_process_view(false);
                    current_selection_ = saved_sel;
                    const std::uint64_t off = model_.virtual_address_to_offset(reg_copy.start_address).value_or(0u);
                    current_selection_.file_offset = off;
                    hex_panel_.navigate_to_range(clamp_to_size_t(off),
                                                 clamp_to_size_t(std::min<std::uint64_t>(reg_copy.size(), 16u)));
                    if (reg_copy.protection.executable) {
                        disassemble_at_offset(off, reg_copy.start_address);
                    }
                }
            }
            last_navigation_selection_ = current_selection_;
            return;
        }

        std::optional<std::uint64_t> nav_offset = current_selection_.file_offset;
        if (model_.is_live_process() && current_selection_.virtual_address) {
            if (const auto live_off = model_.virtual_address_to_offset(*current_selection_.virtual_address)) {
                nav_offset = live_off;
            }
        } else if (!nav_offset && current_selection_.virtual_address) {
            nav_offset = model_.virtual_address_to_offset(*current_selection_.virtual_address);
        }

        if (!nav_offset) {
            last_navigation_selection_ = current_selection_;
            return;
        }

        const std::uint64_t size = current_selection_.size != 0 ? current_selection_.size : 1u;
        hex_panel_.navigate_to_range(clamp_to_size_t(*nav_offset), clamp_to_size_t(size));

        if (current_selection_.preferred_view == PreferredView::Disassembly) {
            const std::uint64_t display_address = current_selection_.virtual_address
                ? *current_selection_.virtual_address
                : *nav_offset;
            disassemble_at_offset(*nav_offset, display_address);
        }

        last_navigation_selection_ = current_selection_;
    }




    void UiApp::disassemble_section(const std::string& section_name, std::size_t max_size) {
        const auto* section = pe_model_.section_by_name(section_name);
        if (!section) {
            fprintf(stderr, "Section '%s' not found\n", section_name.c_str());
            return;
        }

        // Check if section is executable
        if (!(section->characteristics & 0x20000000)) {
            fprintf(stderr, "Warning: Section '%s' is not marked executable\n", section_name.c_str());
        }

        std::size_t size = std::min(max_size, static_cast<std::size_t>(section->raw_size));
        const std::uint8_t* code = pe_model_.data_at_offset(section->raw_offset, size);
        if (!code) {
            fprintf(stderr, "Failed to read section data\n");
            return;
        }

        std::uint64_t va = pe_model_.rva_to_va(section->virtual_address);
        auto instructions = disasm_.disassemble(code, size, va);

        printf("Section: %s (0x%llX - 0x%llX)\n",
               section_name.c_str(), va, va + section->virtual_size);
        printf("----------------------------------------\n");

        for (const auto& inst : instructions) {
            std::string bytes_str;
            for (std::uint8_t b : inst.bytes) {
                char buf[4];
                snprintf(buf, sizeof(buf), "%02X ", b);
                bytes_str += buf;
            }

            printf("%016llX  %-24s  %s\n",
                   inst.address,
                   bytes_str.c_str(),
                   inst.to_string().c_str());
        }
    }
    void UiApp::disassemble_at(std::uint64_t rva, std::size_t size) {
        // Get file offset from RVA
        auto file_offset = pe_model_.rva_to_offset(static_cast<std::uint32_t>(rva));
        if (!file_offset) {
            fprintf(stderr, "Failed to convert RVA 0x%llX to file offset\n", rva);
            return;
        }

        // Get pointer to code
        const std::uint8_t* code = pe_model_.data_at_offset(*file_offset, size);
        if (!code) {
            fprintf(stderr, "Failed to read %zu bytes at offset 0x%zX\n", size, *file_offset);
            return;
        }

        // Convert RVA to VA for disassembly
        std::uint64_t va = pe_model_.rva_to_va(static_cast<std::uint32_t>(rva));

        // Disassemble
        auto instructions = disasm_.disassemble(code, size, va);

        for (const auto& inst : instructions) {
            // Format bytes
            std::string bytes_str;
            for (std::uint8_t b : inst.bytes) {
                char buf[4];
                snprintf(buf, sizeof(buf), "%02X ", b);
                bytes_str += buf;
            }

            printf("%016llX  %-24s  %s\n",
                   inst.address,
                   bytes_str.c_str(),
                   inst.to_string().c_str());
        }
    }

    void UiApp::disassemble_at_offset(std::uint64_t file_offset) {
        const std::uint64_t display_address =
            model_.offset_to_virtual_address(file_offset).value_or(file_offset);
        disassemble_at_offset(file_offset, display_address);
    }

    void UiApp::disassemble_at_offset(std::uint64_t file_offset, std::uint64_t display_address) {
        if (!file_loaded_ || !disasm_.is_initialized()) {
            return;
        }
        const std::uint64_t total_size = model_.view_size();
        if (file_offset >= total_size) {
            return;
        }
        last_disasm_offset_ = file_offset;
        last_disasm_address_ = display_address;

        constexpr std::size_t kWindow = 256;
        const auto sample = model_.read_window_sample(file_offset, kWindow);
        std::size_t readable_len = 0;
        if (sample) {
            while (readable_len < sample->valid.size() && sample->valid[readable_len] != 0) {
                ++readable_len;
            }
        }
        if (readable_len == 0) {
            current_instructions_.clear();
            disasm_status_ = std::format(
                "Memory at 0x{:X} is unreadable (guard page or unmapped region).",
                display_address);
            return;
        }
        disasm_status_.clear();
        current_instructions_ = disasm_.disassemble(sample->bytes.data(), readable_len, display_address);
    }

    void UiApp::refresh_disassembly() {
        if (last_disasm_offset_) {
            disassemble_at_offset(*last_disasm_offset_, last_disasm_address_);
        }
    }

    void UiApp::disassemble_entry_point(std::size_t max_size) {
        current_instructions_.clear();
        auto offset = pe_model_.entry_point_offset();
        if (!offset) {
            Log().error("Failed to get entry point offset\n");
            return;
        }

        // Get the section containing the entry point to limit size
        const auto* section = pe_model_.entry_point_section();
        if (section) {
            // Don't read past section end
            const std::uint32_t offset_in_section = pe_model_.entry_point_rva - section->virtual_address;
            if (offset_in_section >= section->raw_size) {
                Log().error("Entry point is outside the section's raw bytes\n");
                return;
            }
            std::size_t section_remaining = static_cast<std::size_t>(section->raw_size - offset_in_section);
            max_size = std::min(max_size, section_remaining);
        }

        const std::uint8_t* code = pe_model_.data_at_offset(*offset, max_size);
        if (!code) {
            Log().error("Failed to read entry point code\n");
            return;
        }

        std::uint64_t va = pe_model_.entry_point_va();
        current_instructions_ = disasm_.disassemble(code, max_size, va);

        Log().error("Entry Point: 0x%llX\n", va);
        printf("----------------------------------------\n");

        for (const auto& inst : current_instructions_) {
            std::string bytes_str;
            for (std::uint8_t b : inst.bytes) {
                char buf[4];
                snprintf(buf, sizeof(buf), "%02X ", b);
                bytes_str += buf;
            }

            Log().error("%016llX  %-24s  %s\n",
                   inst.address,
                   bytes_str.c_str(),
                   inst.to_string().c_str());
        }
    }

    ImVec4 UiApp::get_mnemonic_color(const std::string& mnemonic) const {
    if (mnemonic.empty()) {
        return ImVec4(1.0f, 1.0f, 1.0f, 1.0f);  // White
    }

    // Branch/control flow - Blue
    if (mnemonic[0] == 'j' ||
        mnemonic == "call" || mnemonic == "ret" || mnemonic == "retn" ||
        mnemonic == "loop" || mnemonic == "loope" || mnemonic == "loopne" ||
        mnemonic == "syscall" || mnemonic == "sysret" ||
        mnemonic == "b" || mnemonic == "bl" || mnemonic == "bx" || mnemonic == "blx" ||
        mnemonic == "cbz" || mnemonic == "cbnz") {
        return ImVec4(0.4f, 0.8f, 1.0f, 1.0f);
    }

    // SIMD/Vector - Green
    if (mnemonic[0] == 'v' ||  // AVX
        mnemonic.find("movap") == 0 || mnemonic.find("movup") == 0 ||
        mnemonic.find("movdq") == 0 || mnemonic.find("movss") == 0 ||
        mnemonic.find("movsd") == 0 || mnemonic.find("addp") == 0 ||
        mnemonic.find("subp") == 0 || mnemonic.find("mulp") == 0 ||
        mnemonic.find("divp") == 0 || mnemonic.find("xmm") != std::string::npos ||
        mnemonic.find("ymm") != std::string::npos ||
        mnemonic.find("zmm") != std::string::npos) {
        return ImVec4(0.5f, 1.0f, 0.5f, 1.0f);
    }

    // NOP/padding - Gray
    if (mnemonic == "nop" || mnemonic == "int3" || mnemonic == "ud2") {
        return ImVec4(0.5f, 0.5f, 0.5f, 1.0f);
    }

    // Data movement - Light yellow
    if (mnemonic.find("mov") == 0 || mnemonic == "lea" ||
        mnemonic == "push" || mnemonic == "pop" ||
        mnemonic == "xchg" || mnemonic == "ldr" || mnemonic == "str") {
        return ImVec4(1.0f, 1.0f, 0.7f, 1.0f);
    }

    // Arithmetic - Orange
    if (mnemonic == "add" || mnemonic == "sub" || mnemonic == "mul" ||
        mnemonic == "div" || mnemonic == "inc" || mnemonic == "dec" ||
        mnemonic == "imul" || mnemonic == "idiv" || mnemonic == "neg") {
        return ImVec4(1.0f, 0.8f, 0.4f, 1.0f);
    }

    // Logic/bitwise - Purple
    if (mnemonic == "and" || mnemonic == "or" || mnemonic == "xor" ||
        mnemonic == "not" || mnemonic == "shl" || mnemonic == "shr" ||
        mnemonic == "sar" || mnemonic == "rol" || mnemonic == "ror" ||
        mnemonic == "test" || mnemonic == "cmp") {
        return ImVec4(0.8f, 0.6f, 1.0f, 1.0f);
    }

    // Compare/test - Cyan
    if (mnemonic == "cmp" || mnemonic == "test" ||
        mnemonic.find("cmp") == 0 || mnemonic.find("test") == 0) {
        return ImVec4(0.4f, 1.0f, 1.0f, 1.0f);
    }

    // Default - White
    return ImVec4(1.0f, 1.0f, 1.0f, 1.0f);
}
} // namespace viewer
