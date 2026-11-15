#include "ui_app.hpp"
#include "graph/layout_edit.hpp"
#include "theme.hpp"
#include "analysis/project.hpp"
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

void activate_panel(const char* name) {
    if (auto* window = ImGui::FindWindowByName(name)) {
        if (window->DockNode && window->DockNode->TabBar)
            window->DockNode->TabBar->NextSelectedTabId = window->TabId;
        ImGui::FocusWindow(window);
    }
}

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
           lhs.virtual_address == rhs.virtual_address && lhs.file_offset == rhs.file_offset &&
           lhs.size == rhs.size && lhs.preferred_view == rhs.preferred_view &&
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

[[nodiscard]] std::string call_graph_node_display_label(const CallGraphNode& node, bool demangle = true) {
    std::string base_label = node.label.empty() ? node.id : node.label;
    if (demangle && node.symbol && !node.symbol->demangled_name.empty() &&
        (node.label.empty() || node.label == node.symbol->name)) {
        base_label = node.symbol->demangled_name;
    }
    std::string label = base_label;
    if (!node.instructions.empty()) {
        for (const auto& instruction : node.instructions)
            label += std::format("\n{:X}  {:6} {}", instruction.address, instruction.mnemonic, instruction.operands);
        return label;
    }
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
    , details_panel_(current_selection_, &model)
    , sections_panel_(model)
    , hex_panel_(model)
    , patch_set_panel_(model, current_selection_)
    , shellcode_panel_(model, current_selection_)
    , imports_panel_(model)
    , exports_panel_(model)
    , symbols_panel_(symbol_index_, current_selection_, model)
    , functions_panel_(model, current_selection_)
    , threads_panel_(model)
    , thread_locals_panel_(model)
    , memory_search_panel_(model)
    , runtime_flags_panel_(model)
    , handlers_panel_(model)
    , references_panel_(reference_index_, annotations_, symbol_index_, current_selection_)
    , strings_panel_(model, strings_index_, reference_index_, annotations_, current_selection_)
    , struct_view_panel_(model, current_selection_)
    , process_internals_panel_(model)
    , log_panel_()
    , pe_headers_panel_(model)
    , pe_imports_panel_(model)
    , pe_exports_panel_(model)
{
    references_panel_.set_visible(false);
    strings_panel_.set_visible(false);
    struct_view_panel_.set_visible(false);
    process_internals_panel_.set_visible(false);
    initialize_decompiler();
    recent_binaries_path_ = decompiler_directory_ / "recent_binaries.ini";
#ifdef _WIN32
    recent_binaries_.load(recent_binaries_path_, decompiler_directory_ / "peelf_viewer.exe");
#else
    recent_binaries_.load(recent_binaries_path_, decompiler_directory_ / "peelf_viewer");
#endif
    if (!recent_binaries_.save(recent_binaries_path_)) Log().error("Could not save recent binary history");
    patch_set_panel_.set_analysis_context(&symbol_index_, &thumb_mode_);
    references_panel_.set_scanner(&reference_scanner_);
    references_panel_.set_navigate_callback([this](std::uint64_t address) {
        navigate_to_address(address, PreferredView::Disassembly);
    });
    references_panel_.set_rebuild_callback([this] { references_dirty_ = true; });
    strings_panel_.set_rebuild_callback([this](std::size_t, bool) { strings_dirty_ = true; });
    strings_panel_.set_string_selected_callback([this](const ExtractedString& s) {
        std::optional<std::uint64_t> nav_offset = model_.virtual_address_to_offset(s.virtual_address);
        if (!nav_offset && !model_.is_live_process()) {
            nav_offset = s.file_offset;
        }
        if (!nav_offset && model_.is_live_process() && model_.navigate_to_virtual_address(s.virtual_address)) {
            sync_live_process_view(false);
            nav_offset = model_.virtual_address_to_offset(s.virtual_address);
        }
        navigation_history_.visit(current_selection_);
        const std::size_t byte_len = std::max<std::size_t>(s.byte_length, 1u);
        current_selection_ = ViewerSelection{
            .kind = SelectionKind::ByteRange,
            .label = "String: " + format_single_line_string_preview(s.preview, 96),
            .file_offset = nav_offset,
            .virtual_address = s.virtual_address,
            .size = byte_len,
            .preferred_view = PreferredView::Hex,
        };
        if (nav_offset) {
            hex_panel_.set_visible(true);
            hex_panel_.navigate_to_range(clamp_to_size_t(*nav_offset), clamp_to_size_t(byte_len));
        }
        last_navigation_selection_ = current_selection_;
        navigation_history_.visit(current_selection_);
    });
    struct_view_panel_.set_extra_types_provider([this]() -> std::span<const DataTypeRecord> {
        return decompiled_.types;
    });
    struct_view_panel_.set_field_selected_callback(
        [this](std::optional<std::uint64_t> window_offset,
               std::optional<std::uint64_t> virtual_address,
               std::uint64_t size,
               std::string label) {
            const std::uint64_t byte_len = std::max<std::uint64_t>(1u, size);
            current_selection_ = ViewerSelection{
                .kind = SelectionKind::ByteRange,
                .label = std::move(label),
                .file_offset = model_.is_live_process() ? std::nullopt : window_offset,
                .virtual_address = virtual_address,
                .size = byte_len,
                .object_index = 0,
                .preferred_view = PreferredView::Hex,
                .graph_root = std::nullopt,
            };
            if (window_offset) {
                hex_panel_.set_visible(true);
                hex_panel_.navigate_to_range(clamp_to_size_t(*window_offset), clamp_to_size_t(byte_len));
            } else if (virtual_address && model_.is_live_process() &&
                       model_.navigate_to_virtual_address(*virtual_address)) {
                sync_live_process_view(false);
                if (const auto off = model_.virtual_address_to_offset(*virtual_address)) {
                    hex_panel_.set_visible(true);
                    hex_panel_.navigate_to_range(clamp_to_size_t(*off), clamp_to_size_t(byte_len));
                }
            }
        });
    struct_view_panel_.set_pointer_activated_callback([this](std::uint64_t target_va) {
        navigate_to_address(target_va, PreferredView::Hex);
    });
    hex_panel_.set_apply_structure_callback([this](std::uint64_t address, bool is_file_offset) {
        open_structure_view({}, address, is_file_offset);
    });
    strings_panel_.set_referrer_activated_callback(
        [this](const StringReferrer& ref, StringReferrerTargetView target) {
            if (target == StringReferrerTargetView::FlowGraph) {
                navigate_to_address(ref.instruction_address, PreferredView::Graph);
                return;
            }
            if (target == StringReferrerTargetView::Decompile) {
                navigate_to_address(ref.function_address.value_or(ref.instruction_address),
                                    PreferredView::Disassembly);
                selected_code_address_ = ref.instruction_address;
                request_decompile();
                return;
            }
            navigate_to_address(ref.instruction_address, PreferredView::Disassembly);
            if (target == StringReferrerTargetView::SyncAllOpen) {
                if (show_call_graph_panel_ && model_.image() != nullptr) {
                    if (const auto root = navigation_graph_root(ref.instruction_address)) {
                        if (!active_graph_root_ || active_graph_root_->virtual_address != root->virtual_address) {
                            pending_call_graph_root_ = *root;
                            pending_call_graph_delay_frames_ = 0;
                        }
                        center_graph_selection_ = true;
                    }
                }
                if (show_decompiler_) {
                    selected_code_address_ = ref.instruction_address;
                    request_decompile();
                }
            }
        });
    references_panel_.set_pause_callback([this] { reference_scanner_.pause(); });
    references_panel_.set_resume_callback([this] { reference_scanner_.resume(reference_index_); });
    references_panel_.set_scan_full_callback([this] {
        if (reference_scanner_.has_resumable_work()) {
            reference_scanner_.scan_full(reference_index_);
        } else if (const auto* image = model_.image()) {
            std::vector<std::uint8_t> snapshot;
            if (model_.changed_intervals().empty()) {
                const auto span = model_.analysis_image_bytes();
                snapshot.assign(span.begin(), span.end());
            } else if (auto patched = model_.read_effective_bytes(0, model_.bytes().size())) {
                snapshot = std::move(*patched);
            }
            if (!snapshot.empty()) {
                reference_scanner_.start(
                    reference_index_,
                    *image,
                    std::move(snapshot),
                    thumb_mode_,
                    std::numeric_limits<std::size_t>::max(),
                    &symbol_index_);
            }
        }
    });
    symbols_panel_.set_display_name_resolver([this](const SymbolRecord& symbol) {
        const auto* annotation = symbol.virtual_address ? annotations_.find(*symbol.virtual_address) : nullptr;
        if (annotation && !annotation->name.empty()) {
            return annotation->name;
        }
        return symbol.display_name(model_.demangle_symbols());
    });
    symbols_panel_.set_demangle_changed_callback([this](bool) { ++symbol_revision_; });
    functions_panel_.set_demangle_changed_callback([this](bool) { ++symbol_revision_; });
    hex_panel_.set_byte_activated_callback([this](std::size_t off, std::size_t size) {
        current_selection_ = ViewerSelection{
            .kind = SelectionKind::ByteRange,
            .label = "Hex selection",
            .file_offset = off,
            .virtual_address = model_.offset_to_virtual_address(off),
            .size = size,
            .preferred_view = PreferredView::Hex
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

    auto on_toggle_pause = [this]() {
        if (!model_.is_live_process()) {
            return;
        }
        const peelf::SubsystemStatus st = model_.is_process_suspended()
            ? model_.resume_process()
            : model_.suspend_process();
        if (st.availability == peelf::Availability::Unavailable) {
            Log().warn("Process pause/resume: {}", st.detail);
        } else {
            Log().info("{}", st.detail);
        }
    };

    file_panel_.set_attach_requested_callback([this]() { open_attach_process_modal(); });
    file_panel_.set_refresh_requested_callback(on_refresh_map);
    file_panel_.set_detach_requested_callback(on_detach_proc);
    file_panel_.set_pause_toggle_callback(on_toggle_pause);

    memory_map_panel_.set_attach_requested_callback([this]() {
        open_attach_process_modal();
    });
    memory_map_panel_.set_refresh_requested_callback(on_refresh_map);
    memory_map_panel_.set_detach_requested_callback(on_detach_proc);
    memory_map_panel_.set_pause_toggle_callback(on_toggle_pause);
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
            const auto disasm_win = static_cast<std::size_t>(
                std::clamp<std::uint64_t>(reg_copy.size(), 4096u, 65536u));
            disassemble_at_offset(offset, reg_copy.start_address, disasm_win);
            show_disassembly_panel_ = true;
            focus_listing_ = true;
        }
        last_navigation_selection_ = current_selection_;
    });

    functions_panel_.set_function_activated_callback([this](std::uint64_t va, bool want_decompile) {
        navigate_to_address(va, PreferredView::Disassembly);
        if (want_decompile) {
            request_decompile();
        }
    });
    threads_panel_.set_address_activated_callback([this](std::uint64_t va, PreferredView pv, bool want_decompile) {
        navigate_to_address(va, pv);
        if (want_decompile) {
            request_decompile();
        }
    });
    thread_locals_panel_.set_address_activated_callback([this](std::uint64_t va, PreferredView pv) {
        navigate_to_address(va, pv);
    });
    memory_search_panel_.set_address_activated_callback([this](std::uint64_t va, std::size_t match_size) {
        navigate_to_address(va, PreferredView::Hex);
        if (const auto off = model_.virtual_address_to_offset(va)) {
            hex_panel_.navigate_to_range(clamp_to_size_t(*off), std::max<std::size_t>(1u, match_size));
        }
    });
    runtime_flags_panel_.set_address_activated_callback([this](std::uint64_t va, PreferredView pv) {
        navigate_to_address(va, pv);
    });
    handlers_panel_.set_address_activated_callback([this](std::uint64_t va, PreferredView pv) {
        navigate_to_address(va, pv);
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
                const auto disasm_win = static_cast<std::size_t>(
                    std::clamp<std::uint64_t>(range_size, 4096u, 65536u));
                disassemble_at_offset(*nav_offset, section.virtual_address, disasm_win);
            }
            last_navigation_selection_ = current_selection_;
        });
    symbols_panel_.set_symbol_activated_callback([this](const SymbolRecord& symbol, std::uint64_t object_index) {
        focus_graph_ = true;
        activate_panel(details_panel_.name().c_str());
        activate_panel("Disassembly");
        const peelf::IBinaryImage* img = model_.image();
        if (img == nullptr) {
            return;
        }

        current_selection_ = ViewerSelection{
            .kind = SelectionKind::Symbol, .label = symbol.name,
            .file_offset = symbol.file_offset, .virtual_address = symbol.virtual_address,
            .size = symbol.size, .object_index = object_index,
            .preferred_view = PreferredView::Details
        };
        auto file_offset = symbol.virtual_address ? model_.virtual_address_to_offset(*symbol.virtual_address) : symbol.file_offset;
        if (!file_offset && model_.is_live_process() && symbol.virtual_address && model_.navigate_to_virtual_address(*symbol.virtual_address)) {
            sync_live_process_view(false);
            file_offset = model_.virtual_address_to_offset(*symbol.virtual_address);
        }
        pending_call_graph_root_.reset();
        current_instructions_.clear();
        disassembly_location_.reset();
        hex_panel_.clear_selection();
        if (!file_offset) {
            Log().warn("Symbol '{}' at 0x{:X} does not map to file bytes",
                       symbol.name.empty() ? "<unnamed>" : symbol.name,
                       symbol.virtual_address.value_or(0));
            current_instructions_.clear();
            return;
        }
        if (*file_offset > static_cast<std::uint64_t>(std::numeric_limits<std::size_t>::max()) ||
            symbol.size > static_cast<std::uint64_t>(std::numeric_limits<std::size_t>::max())) {
            Log().warn("Symbol '{}' range is too large for this platform",
                       symbol.name.empty() ? "<unnamed>" : symbol.name);
            return;
        }

        const std::size_t highlight_size = symbol.size != 0
            ? static_cast<std::size_t>(symbol.size)
            : std::size_t{1};
        current_selection_ = ViewerSelection{
            .kind = SelectionKind::Symbol,
            .label = symbol.name.empty() ? "<unnamed>" : symbol.name,
            .file_offset = *file_offset,
            .virtual_address = symbol.virtual_address,
            .size = symbol.size,
            .object_index = object_index,
            .preferred_view = symbol_has_code(*img, symbol) ? PreferredView::Graph : PreferredView::Hex
        };
        hex_panel_.navigate_to_range(static_cast<std::size_t>(*file_offset), highlight_size);
        if (symbol_has_code(*img, symbol)) {
            current_selection_.graph_root = symbol;
            disassemble_at_offset(static_cast<std::size_t>(*file_offset), *symbol.virtual_address);
            pending_call_graph_root_ = symbol;
            pending_call_graph_delay_frames_ = 1;
            show_call_graph_panel_ = true;
            call_graph_status_ = "Analyzing " + symbol.name;
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
    decompile_stop_.request_stop();
    if (call_graph_texture_) {
        vulkan_.destroy_texture(*call_graph_texture_);
        call_graph_texture_.reset();
    }
}

void UiApp::render() {
    render_main_menu();
    auto* viewport = ImGui::GetMainViewport();
    if (ImGui::BeginViewportSideBar("##workspace-actions", viewport, ImGuiDir_Up,
            ImGui::GetFrameHeight() + ImGui::GetStyle().WindowPadding.y * 2,
            ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoSavedSettings)) {
        ImGui::AlignTextToFramePadding();
        ImGui::TextColored(ImGui::GetStyleColorVec4(ImGuiCol_CheckMark), "PE / ELF");
        ImGui::SameLine(0, 24);
        if (ImGui::Button("Open binary") && on_open_file_) on_open_file_();
        ImGui::SameLine();
        if (ImGui::Button("Attach process")) open_attach_process_modal();
        ImGui::SameLine();
        ImGui::BeginDisabled(!model_.has_file());
        if (ImGui::Button("Functions")) {
            functions_panel_.set_visible(true);
            activate_panel(functions_panel_.name().c_str());
        }
        ImGui::SameLine();
        if (ImGui::Button("Strings")) open_strings();
        ImGui::SameLine();
        if (ImGui::Button("Decompile")) request_decompile();
        ImGui::SameLine();
        if (ImGui::Button("Search")) {
            memory_search_panel_.set_visible(true);
            activate_panel(memory_search_panel_.name().c_str());
        }
        if (model_.is_live_process()) {
            ImGui::SameLine();
            if (ImGui::Button(model_.is_process_suspended() ? "Resume" : "Pause")) {
                const auto st = model_.is_process_suspended() ? model_.resume_process() : model_.suspend_process();
                Log().info("{}", st.detail);
            }
            ImGui::SameLine();
            if (ImGui::Button("Threads")) {
                threads_panel_.set_visible(true);
                activate_panel(threads_panel_.name().c_str());
            }
        }
        ImGui::SameLine();
        ImGui::BeginDisabled(!navigation_history_.can_back());
        if (ImGui::Button("Back")) navigate_history(false);
        ImGui::EndDisabled();
        ImGui::SameLine();
        ImGui::BeginDisabled(!navigation_history_.can_forward());
        if (ImGui::Button("Forward")) navigate_history(true);
        ImGui::EndDisabled();
        ImGui::SameLine();
        if (ImGui::Button("Listing")) switch_analysis_view(false);
        ImGui::SameLine();
        if (ImGui::Button("Graph")) switch_analysis_view(true);
        ImGui::SameLine();
        if (ImGui::Button("Entry") && model_.image()) navigate_to_address(model_.image()->entry_point());
        ImGui::SameLine();
        ImGui::SetNextItemWidth(ImGui::GetFontSize() * 9);
        ImGui::InputScalar("##JumpVA", ImGuiDataType_U64, &jump_address_, nullptr, nullptr, "%llX", ImGuiInputTextFlags_CharsHexadecimal);
        if (ImGui::IsItemHovered()) ImGui::SetTooltip("Jump to virtual address (hexadecimal)");
        ImGui::SameLine();
        if (ImGui::Button("Jump") && model_.has_file()) {
            navigate_to_address(jump_address_);
        }
        ImGui::SameLine();
        if (ImGui::Button("References")) open_references();
        if (!model_.is_live_process()) {
            ImGui::SameLine();
            if (ImGui::Button("Patches")) patch_set_panel_.set_visible(true);
            ImGui::SameLine();
            if (ImGui::Button("Export copy") && on_save_patched_as_) on_save_patched_as_();
        }
        ImGui::EndDisabled();
        ImGui::SameLine(0, 24);
        ImGui::TextDisabled("%s", model_.has_file()
            ? std::filesystem::path(model_.file_info().path).filename().string().c_str()
            : "Ready to inspect");
    }
    ImGui::End();
    if (ImGui::BeginViewportSideBar("##section-map", viewport, ImGuiDir_Up,
            ImGui::GetFrameHeight() + ImGui::GetStyle().WindowPadding.y * 2,
            ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoSavedSettings)) {
        ImGui::AlignTextToFramePadding();
        ImGui::TextDisabled("SEGMENTS");
        if (const auto* image = model_.image()) {
            for (const auto& section : image->sections()) {
                const std::uint64_t sec_size = std::max(section.file_size, section.virtual_size);
                if (sec_size == 0) continue;
                ImGui::SameLine();
                ImGui::PushID(static_cast<int>((section.virtual_address ^ section.file_offset) & 0x7FFFFFFFu));
                ImGui::PushStyleColor(ImGuiCol_Button, ImGui::GetStyleColorVec4(section.executable ? ImGuiCol_HeaderActive : ImGuiCol_FrameBg));
                if (ImGui::Button(section.name.c_str())) {
                    const auto nav_off = model_.is_live_process()
                        ? model_.virtual_address_to_offset(section.virtual_address)
                        : std::optional<std::uint64_t>(section.file_offset);
                    if (nav_off) {
                        hex_panel_.navigate_to_range(clamp_to_size_t(*nav_off), 1);
                        if (section.executable) {
                            const auto disasm_win = static_cast<std::size_t>(
                                std::clamp<std::uint64_t>(sec_size, 4096u, 65536u));
                            disassemble_at_offset(*nav_off, section.virtual_address, disasm_win);
                        }
                        current_selection_ = ViewerSelection{
                            .kind = SelectionKind::Section,
                            .label = section.name,
                            .file_offset = *nav_off,
                            .virtual_address = section.virtual_address,
                            .size = sec_size,
                            .preferred_view = section.executable ? PreferredView::Disassembly : PreferredView::Hex
                        };
                    }
                }
                ImGui::PopStyleColor();
                if (ImGui::IsItemHovered()) ImGui::SetTooltip("VA 0x%llX | %llu bytes%s",
                    static_cast<unsigned long long>(section.virtual_address), static_cast<unsigned long long>(sec_size),
                    section.executable ? " | executable" : "");
                ImGui::PopID();
            }
        } else { ImGui::SameLine(); ImGui::TextDisabled("Open an image to navigate its sections"); }
    }
    ImGui::End();
    render_dockspace();
    render_attach_process_modal();

    file_panel_.draw();
    memory_map_panel_.draw();
    structure_panel_.draw();
    apply_structure_selection_navigation();
    details_panel_.draw();
    sections_panel_.draw();
    ImGui::PushFont(code_font_, 0.0f);
    hex_panel_.draw();
    ImGui::PopFont();
    patch_set_panel_.draw();
    shellcode_panel_.draw();
    imports_panel_.draw();
    exports_panel_.draw();
    symbols_panel_.draw();
    functions_panel_.draw();
    threads_panel_.draw();
    thread_locals_panel_.draw();
    memory_search_panel_.draw();
    runtime_flags_panel_.draw();
    handlers_panel_.draw();
    if (show_data_types_) render_data_types();
    references_panel_.draw();
    strings_panel_.draw();
    struct_view_panel_.draw();
    process_internals_panel_.draw();
    if (show_decompiler_) render_decompiler();
    if (focus_references_) {
        activate_panel(references_panel_.name().c_str());
        focus_references_ = false;
    }
    if (focus_strings_) {
        activate_panel(strings_panel_.name().c_str());
        focus_strings_ = false;
    }
    if (focus_struct_view_) {
        activate_panel(struct_view_panel_.name().c_str());
        focus_struct_view_ = false;
    }
    pe_headers_panel_.draw();
    pe_imports_panel_.draw();
    pe_exports_panel_.draw();
    log_panel_.draw();

    if (show_disassembly_panel_) {
        ImGui::PushFont(code_font_, 0.0f);
        render_disassembly_panel();
        ImGui::PopFont();
    }
    if (show_call_graph_panel_) {
        render_call_graph_panel();
        if (focus_graph_) { activate_panel("Flow Graph"); focus_graph_ = false; }
    }
    if (show_demo_window_)
        ImGui::ShowDemoWindow(&show_demo_window_);
    if (focus_listing_) { activate_panel("Disassembly"); focus_listing_ = false; }
    navigation_history_.visit(current_selection_);
    if (focus_workspace_) {
        activate_panel(symbols_panel_.name().c_str());
        activate_panel(details_panel_.name().c_str());
        activate_panel("Disassembly");
        focus_workspace_ = false;
    }
}

peelf::Result<void> UiApp::save_project(const std::filesystem::path& path) {
    if (!model_.image()) return peelf::make_error("No binary loaded");
    std::error_code ec;
    if (std::filesystem::equivalent(path, model_.file_info().path, ec)) return peelf::make_error("Project cannot replace the source binary");
    AnalysisProject project;
    project.source = std::filesystem::absolute(model_.file_info().path).string();
    project.source_size = model_.bytes().size(); project.fingerprint = binary_fingerprint(model_.bytes());
    project.patches = model_.changed_intervals(); project.annotations = annotations_.records(); project.thumb = thumb_mode_;
    navigation_history_.visit(current_selection_);
    project.history = navigation_history_.entries(); project.cursor = navigation_history_.cursor();
    for (const auto& s : symbol_index_.records()) if (s.source == SymbolSource::DebugSymbol && s.virtual_address)
        project.symbols.push_back({s.name, *s.virtual_address >= model_.image()->image_base() ? *s.virtual_address - model_.image()->image_base() : 0,
            *s.virtual_address, s.size, s.function.value_or(false)});
    std::size_t size = 0; const char* layout = ImGui::SaveIniSettingsToMemory(&size); project.layout.assign(layout,size);
    return write_analysis_file(path, encode_project(project));
}

peelf::Result<void> UiApp::open_project(const std::filesystem::path& path) {
    auto text = read_project_file(path); if (!text) return std::unexpected(text.error());
    auto project = decode_project(*text); if (!project) return std::unexpected(project.error());
    auto source = std::filesystem::path(project->source); if (source.is_relative()) source = path.parent_path() / source;
    BinaryModel restored;
    if (!restored.load_file(source.string())) return peelf::make_error("Cannot open project's source binary");
    auto patches = restore_project_patches(restored,*project); if (!patches) return patches;
    model_ = std::move(restored); on_file_loaded();
    thumb_mode_ = project->thumb;
    if (model_.image()->architecture() == peelf::Architecture::ARM) disasm_.set_thumb_mode(thumb_mode_);
    model_.add_debug_symbols(project->symbols);
    symbol_index_ = model_.symbol_index();
    for (auto& [address,note] : project->annotations) annotations_.set(address,std::move(note.name),std::move(note.comment));
    navigation_history_.restore(project->history,project->cursor);
    if (!project->history.empty()) {
        current_selection_ = project->history[project->cursor];
        if (current_selection_.virtual_address) {
            auto selection = current_selection_; navigate_to_address(*selection.virtual_address,selection.preferred_view);
            current_selection_ = selection; last_navigation_selection_ = selection;
        } else { last_navigation_selection_.reset(); apply_structure_selection_navigation(); }
        navigation_history_.restore(project->history,project->cursor);
    }
    if (!project->layout.empty()) ImGui::LoadIniSettingsFromMemory(project->layout.c_str(),project->layout.size());
    focus_workspace_ = false; references_dirty_ = true;
    return {};
}

peelf::Result<void> UiApp::save_patch_report(const std::filesystem::path& path) {
    if (!model_.image()) return peelf::make_error("No binary loaded");
    std::error_code ec;
    if (std::filesystem::equivalent(path,model_.file_info().path,ec)) return peelf::make_error("Report cannot replace the source binary");
    return write_analysis_file(path,patch_report(model_));
}

void UiApp::open_references() {
    references_panel_.set_visible(true);
    focus_references_ = true;
}

void UiApp::open_strings() {
    strings_panel_.set_visible(true);
    focus_strings_ = true;
}

void UiApp::open_structure_view(std::string_view type_name,
                                std::optional<std::uint64_t> address,
                                bool is_file_offset) {
    struct_view_panel_.set_visible(true);
    focus_struct_view_ = true;
    if (address) {
        struct_view_panel_.apply_structure_at(type_name, *address, is_file_offset, 1);
    } else if (!type_name.empty()) {
        const bool use_off = !model_.is_live_process() && !current_selection_.virtual_address.has_value();
        const std::uint64_t addr = use_off
            ? current_selection_.file_offset.value_or(0)
            : current_selection_.virtual_address.value_or(model_.view_base_address());
        struct_view_panel_.apply_structure_at(type_name, addr, use_off, 1);
    }
}

void UiApp::rebuild_strings() {
    StringScanOptions opts;
    opts.min_length = strings_panel_.requested_min_length();
    opts.include_all_live_regions = strings_panel_.scan_all_live_regions();

    if (model_.is_live_process() && model_.process_session() != nullptr) {
        std::optional<std::uint64_t> active_base;
        if (const auto mod_idx = model_.active_module_index();
            mod_idx && *mod_idx < model_.process_modules().size()) {
            active_base = model_.process_modules()[*mod_idx].base_address;
        }
        if (!opts.include_all_live_regions && model_.image() != nullptr &&
            !model_.analysis_image_bytes().empty()) {
            strings_index_ = StringsIndex::extract(*model_.image(), model_.analysis_image_bytes(), opts);
        } else {
            strings_index_ = StringsIndex::extract_live(
                *model_.process_session(),
                model_.memory_regions(),
                model_.image(),
                active_base,
                opts);
        }
    } else if (const auto* image = model_.image()) {
        if (model_.changed_intervals().empty()) {
            strings_index_ = StringsIndex::extract(*image, model_.analysis_image_bytes(), opts);
        } else if (auto patched = model_.read_effective_bytes(0, model_.bytes().size())) {
            strings_index_ = StringsIndex::extract(*image, *patched, opts);
        } else {
            strings_index_.clear();
        }
    } else {
        strings_index_.clear();
    }

    strings_index_.refresh_xrefs(
        reference_index_, &model_.function_index(), &symbol_index_, symbol_revision_);
    strings_revision_ = model_.edit_revision();
    strings_dirty_ = false;
}

void UiApp::rebuild_references() {
    const auto* image = model_.image();
    if (!image) return;
    reference_scanner_.cancel(&reference_index_);

    std::span<const std::uint8_t> direct_span;
    std::vector<std::uint8_t> owned_bytes;
    if (model_.changed_intervals().empty()) {
        direct_span = model_.analysis_image_bytes();
    } else if (auto bytes = model_.read_effective_bytes(0, model_.bytes().size())) {
        owned_bytes = std::move(*bytes);
        direct_span = owned_bytes;
    } else {
        reference_index_ = {};
        Log().warn("Unable to read patched bytes for reference analysis");
        reference_revision_ = model_.edit_revision();
        reference_thumb_mode_ = thumb_mode_;
        references_dirty_ = false;
        return;
    }

    if (direct_span.size() <= ReferenceIndex::kDefaultChunkBytes) {
        reference_index_ = ReferenceIndex::build(
            *image, direct_span, thumb_mode_, ReferenceIndex::kDefaultByteBudget, &symbol_index_);
    } else {
        if (owned_bytes.empty()) {
            owned_bytes.assign(direct_span.begin(), direct_span.end());
        }
        reference_scanner_.start(
            reference_index_,
            *image,
            std::move(owned_bytes),
            thumb_mode_,
            ReferenceIndex::kDefaultByteBudget,
            &symbol_index_);
    }
    reference_revision_ = model_.edit_revision();
    reference_thumb_mode_ = thumb_mode_;
    references_dirty_ = false;
}

void UiApp::render_main_menu() {
    if (!ImGui::GetIO().WantTextInput && ImGui::IsKeyPressed(ImGuiKey_F5)) {
        if (ImGui::GetIO().KeyCtrl && model_.is_live_process()) {
            if (auto result = model_.refresh_process_map()) sync_live_process_view(false);
            else Log().error("Refresh failed: {}", result.error().message);
        } else if (!ImGui::GetIO().KeyCtrl) request_decompile();
    }
    if (!ImGui::GetIO().WantTextInput && ImGui::Shortcut(ImGuiKey_X, ImGuiInputFlags_RouteGlobal)) open_references();
    if (!ImGui::GetIO().WantTextInput) {
        if (ImGui::IsKeyChordPressed(ImGuiMod_Alt | ImGuiKey_LeftArrow) ||
            ImGui::IsKeyChordPressed(ImGuiKey_Backspace)) navigate_history(false);
        if (ImGui::IsKeyChordPressed(ImGuiMod_Alt | ImGuiKey_RightArrow) ||
            ImGui::IsKeyChordPressed(ImGuiMod_Shift | ImGuiKey_Backspace)) navigate_history(true);
    }
    if (ImGui::Shortcut(ImGuiMod_Ctrl | ImGuiKey_O, ImGuiInputFlags_RouteGlobal) && on_open_file_) on_open_file_();
    if (ImGui::Shortcut(ImGuiMod_Ctrl | ImGuiMod_Shift | ImGuiKey_S, ImGuiInputFlags_RouteGlobal) && model_.has_file() && on_save_patched_as_) on_save_patched_as_();
    if (!ImGui::BeginMainMenuBar())
        return;

    if (ImGui::BeginMenu("File")) {
        if (ImGui::MenuItem("Open...", "Ctrl+O")) {
            if (on_open_file_) { on_open_file_(); }
        }
        if (ImGui::BeginMenu("Recent Binaries")) {
            std::optional<std::filesystem::path> selected;
            for (const auto& path : recent_binaries_.paths()) {
                const auto utf8 = path.generic_u8string();
                const std::string label(utf8.begin(), utf8.end());
                ImGui::PushID(label.c_str());
                if (ImGui::MenuItem(label.c_str())) selected = path;
                ImGui::PopID();
            }
            ImGui::EndMenu();
            if (selected) {
                BinaryModel opened;
                if (opened.load_file(selected->string())) {
                    model_ = std::move(opened);
                    on_file_loaded();
                } else Log().error("Cannot open recent binary: {}", selected->string());
            }
        }
        if (ImGui::MenuItem("Open Analysis Project...", nullptr, false, static_cast<bool>(on_analysis_file_))) on_analysis_file_(0);
        if (ImGui::MenuItem("Save Analysis Project...", nullptr, false, model_.has_file() && static_cast<bool>(on_analysis_file_))) on_analysis_file_(1);
        if (ImGui::MenuItem("Export Patch Report...", nullptr, false, model_.has_file() && static_cast<bool>(on_analysis_file_))) on_analysis_file_(2);
        if (ImGui::MenuItem("Attach to Process...", "Ctrl+P")) {
            open_attach_process_modal();
        }
        if (ImGui::MenuItem("Refresh Process Memory Map", "Ctrl+F5", false, model_.is_live_process())) {
            auto res = model_.refresh_process_map();
            if (res) {
                sync_live_process_view(false);
                Log().info("Refreshed process memory map");
            } else {
                Log().error("Refresh failed: {}", res.error().message);
            }
        }
        if (ImGui::MenuItem(model_.is_process_suspended() ? "Resume Process" : "Pause Process",
                            nullptr,
                            false,
                            model_.is_live_process())) {
            const auto st = model_.is_process_suspended() ? model_.resume_process() : model_.suspend_process();
            Log().info("{}", st.detail);
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
        ImGui::Separator();
        if (ImGui::MenuItem("Exit", "Alt+F4")) {
            if (on_exit_) on_exit_();
        }
        ImGui::EndMenu();
    }

    if (ImGui::BeginMenu("Edit")) {
        const auto* image = model_.editable_image();
        if (ImGui::MenuItem("Undo patch", nullptr, false, !model_.is_live_process() && image && image->can_undo())) {
            if (auto result = model_.undo_patch(); !result) Log().error("{}", result.error().message);
        }
        if (ImGui::MenuItem("Redo patch", nullptr, false, !model_.is_live_process() && image && image->can_redo())) {
            if (auto result = model_.redo_patch(); !result) Log().error("{}", result.error().message);
        }
        ImGui::Separator();
        if (ImGui::MenuItem("Memory Search", nullptr, false, model_.has_file())) {
            memory_search_panel_.set_visible(true);
            activate_panel(memory_search_panel_.name().c_str());
        }
        if (ImGui::MenuItem("Patch workspace", nullptr, false, !model_.is_live_process())) patch_set_panel_.set_visible(true);
        if (ImGui::MenuItem("Byte input workspace", nullptr, false, !model_.is_live_process())) shellcode_panel_.set_visible(true);
        ImGui::EndMenu();
    }
    if (ImGui::BeginMenu("Navigate")) {
        if (ImGui::MenuItem("Back", "Alt+Left", false, navigation_history_.can_back())) navigate_history(false);
        if (ImGui::MenuItem("Forward", "Alt+Right", false, navigation_history_.can_forward())) navigate_history(true);
        ImGui::Separator();
        if (ImGui::MenuItem("Entry point", nullptr, false, model_.image() != nullptr)) {
            const auto* image = model_.image();
            navigate_to_address(image->entry_point());
        }
        if (ImGui::MenuItem("Functions")) {
            functions_panel_.set_visible(true);
            activate_panel(functions_panel_.name().c_str());
        }
        if (ImGui::MenuItem("Symbols")) symbols_panel_.set_visible(true);
        if (ImGui::MenuItem("Strings", nullptr, false, model_.has_file())) open_strings();
        if (ImGui::MenuItem("Threads & Stack", nullptr, false, model_.is_live_process())) {
            threads_panel_.set_visible(true);
            activate_panel(threads_panel_.name().c_str());
        }
        if (ImGui::MenuItem("Thread Locals", nullptr, false, model_.has_file())) {
            thread_locals_panel_.set_visible(true);
            activate_panel(thread_locals_panel_.name().c_str());
        }
        if (ImGui::MenuItem("Memory Search", nullptr, false, model_.has_file())) {
            memory_search_panel_.set_visible(true);
            activate_panel(memory_search_panel_.name().c_str());
        }
        if (ImGui::MenuItem("PEB / TEB & Flags", nullptr, false, model_.has_file())) {
            runtime_flags_panel_.set_visible(true);
            activate_panel(runtime_flags_panel_.name().c_str());
        }
        if (ImGui::MenuItem("Handlers (VEH / SEH / atexit)", nullptr, false, model_.has_file())) {
            handlers_panel_.set_visible(true);
            activate_panel(handlers_panel_.name().c_str());
        }
        if (ImGui::MenuItem("Process Internals (Handles / Sockets / Security)",
                            nullptr,
                            false,
                            model_.is_live_process())) {
            process_internals_panel_.set_visible(true);
            activate_panel(process_internals_panel_.name().c_str());
        }
        if (ImGui::MenuItem("References & Notes", "X", false, model_.has_file())) open_references();
        if (ImGui::MenuItem("Decompile selection", "F5", false, model_.has_file())) request_decompile();
        if (ImGui::MenuItem("Structure")) structure_panel_.set_visible(true);
        ImGui::EndMenu();
    }
    if (ImGui::BeginMenu("Analyze")) {
        ImGui::MenuItem("Disassembly", nullptr, &show_disassembly_panel_);
        ImGui::MenuItem("Call graph", nullptr, &show_call_graph_panel_);
        if (ImGui::MenuItem("Rebuild loaded call graph", nullptr, false, model_.has_file())) queue_call_graph_sample(CallGraphSample::LoadedImage);
        ImGui::EndMenu();
    }
    if (ImGui::BeginMenu("View")) {
        ImGui::MenuItem("Data Structures", nullptr, &show_data_types_);
        {
            bool demangle = model_.demangle_symbols();
            if (ImGui::MenuItem("Demangle symbols", nullptr, &demangle)) {
                model_.set_demangle_symbols(demangle);
                ++symbol_revision_;
            }
        }
        if (ImGui::MenuItem("Reset Layout")) {
            reset_dock_layout_ = true;
        }
        ImGui::Separator();
        if (ImGui::MenuItem("Reload theme")) ui::load_theme();
        if (ImGui::BeginMenu("Interface scale")) {
            for (const float scale : {1.0f, 1.25f, 1.5f, 2.0f}) {
                const auto label = std::format("{:.0f}%", scale * 100);
                if (ImGui::MenuItem(label.c_str(), nullptr, ImGui::GetStyle().FontScaleMain == scale))
                    ImGui::GetStyle().FontScaleMain = scale;
            }
            ImGui::EndMenu();
        }

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

        for (UiPanel* extra : {static_cast<UiPanel*>(&functions_panel_),
                               static_cast<UiPanel*>(&strings_panel_),
                               static_cast<UiPanel*>(&struct_view_panel_),
                               static_cast<UiPanel*>(&references_panel_),
                               static_cast<UiPanel*>(&threads_panel_),
                               static_cast<UiPanel*>(&thread_locals_panel_),
                               static_cast<UiPanel*>(&memory_search_panel_),
                               static_cast<UiPanel*>(&runtime_flags_panel_),
                               static_cast<UiPanel*>(&handlers_panel_),
                               static_cast<UiPanel*>(&process_internals_panel_)}) {
            bool v = extra->visible();
            if (ImGui::MenuItem(extra->name().c_str(), nullptr, &v)) {
                extra->set_visible(v);
            }
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
            ImGui::MenuItem("Flow Graph", nullptr, &show_call_graph_panel_);
        }

        {
            bool v = log_panel_.visible();
            if (ImGui::MenuItem(log_panel_.name().c_str(), nullptr, &v))
                log_panel_.set_visible(v);
        }

        ImGui::EndMenu();
    }

    if (ImGui::BeginMenu("Help")) {
        if (ImGui::MenuItem("About PE/ELF Explorer")) show_about_ = true;
        ImGui::EndMenu();
    }
    ImGui::EndMainMenuBar();
    if (show_about_) {
        ImGui::OpenPopup("About PE/ELF Explorer");
        show_about_ = false;
    }
    if (ImGui::BeginPopupModal("About PE/ELF Explorer", nullptr, ImGuiWindowFlags_AlwaysAutoResize)) {
        ImGui::TextUnformatted("PE/ELF Explorer");
        ImGui::Separator();
        ImGui::TextUnformatted("Inspect binaries, resolve symbols, and stage byte patches.");
        ImGui::Spacing();
        ImGui::TextDisabled("Ctrl+O  Open binary    |    Ctrl+Shift+S  Export patched copy");
        ImGui::TextDisabled("Theme: resources/theme.ini  |  View > Reload theme");
        ImGui::Spacing();
        if (ImGui::Button("Close", ImVec2(100, 0))) ImGui::CloseCurrentPopup();
        ImGui::EndPopup();
    }
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

    const ImGuiID dockspace_id = ImGui::GetID("AnalysisWorkspaceV7");
    const ImGuiDockNodeFlags dock_flags = ImGuiDockNodeFlags_None;
    const bool compact = viewport->WorkSize.x < ImGui::GetFontSize() * 100.0f;
    if (reset_dock_layout_ || ImGui::DockBuilderGetNode(dockspace_id) == nullptr ||
        (compact_dock_layout_ && *compact_dock_layout_ != compact)) {
        build_default_dock_layout(dockspace_id, viewport->WorkSize);
        reset_dock_layout_ = false;
    }
    compact_dock_layout_ = compact;
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
    if (decompile_job_.valid() && decompile_job_.wait_for(std::chrono::seconds(0)) == std::future_status::ready) {
        try {
            auto result = decompile_job_.get();
            if (decompile_generation_ == file_generation_) {
                if (pending_decompile_cache_key_ && result.status == DecompileStatus::Ready) {
                    decompile_cache_.put(*pending_decompile_cache_key_, result);
                }
                decompiled_ = std::move(result);
            }
            pending_decompile_cache_key_.reset();
        } catch (const std::exception& error) {
            pending_decompile_cache_key_.reset();
            decompiled_ = {DecompileStatus::Failed,"Decompiler",error.what()};
        }
    }
    reference_scanner_.poll(reference_index_);
    if (reference_revision_ != model_.edit_revision() || reference_thumb_mode_ != thumb_mode_)
        references_dirty_ = true;
    if ((references_panel_.visible() || strings_panel_.visible() || show_call_graph_panel_) &&
        references_dirty_ && model_.image())
        rebuild_references();
    if (strings_revision_ != model_.edit_revision())
        strings_dirty_ = true;
    if (strings_panel_.visible() && model_.has_file()) {
        if (strings_dirty_) {
            rebuild_strings();
        }
        strings_index_.refresh_xrefs(
            reference_index_, &model_.function_index(), &symbol_index_, symbol_revision_);
    }
    if (annotation_revision_ != annotations_.revision()) {
        annotation_revision_ = annotations_.revision();
        if (active_graph_root_) pending_call_graph_root_ = active_graph_root_;
    }
    if (active_graph_root_ && graph_revision_ != model_.edit_revision()) {
        pending_call_graph_root_ = active_graph_root_;
        graph_revision_ = model_.edit_revision();
    }
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
            active_graph_root_ = root;
            graph_revision_ = model_.edit_revision();
            graph_pan_ = {};
            graph_zoom_ = 1.0f;
            SymbolRecord root_for_extent = root;
            if (root.virtual_address) {
                root_for_extent.file_offset = img->virtual_address_to_file_offset(*root.virtual_address);
            }
            const std::size_t analysis_size = model_.analysis_image_size();
            if (function_cfg_ && root_for_extent.file_offset && root_for_extent.virtual_address &&
                *root_for_extent.file_offset < analysis_size) {
                const auto extent = discover_function_extent(*img, symbol_index_, root_for_extent, analysis_size);
                if (!extent) {
                    call_graph_status_ = "No executable extent available for " + root.name;
                    return;
                }
                const auto size = static_cast<std::size_t>(extent->size);
                if (const auto bytes = model_.read_virtual_bytes(extent->virtual_address, size)) {
                    const auto window_off = model_.virtual_address_to_offset(extent->virtual_address)
                        .value_or(extent->file_offset);
                    const GraphByteReader va_reader = [this](std::uint64_t va, std::size_t len)
                        -> std::vector<std::uint8_t> {
                        auto res = model_.read_virtual_bytes(va, len);
                        return res ? std::move(*res) : std::vector<std::uint8_t>{};
                    };
                    load_call_graph_from_graph(
                        build_function_cfg_call_graph(
                            *bytes,
                            *root_for_extent.virtual_address,
                            img->architecture(),
                            img->endianness(),
                            static_cast<std::size_t>(window_off),
                            root.name,
                            thumb_mode_,
                            extent->source == FunctionExtentSource::ExecutableRegion ||
                                extent->source == FunctionExtentSource::NextSymbol,
                            va_reader),
                        "function_cfg");
                    if (current_call_graph_) {
                        call_graph_status_ = root.name + std::format(
                            "  |  {} bytes  |  {}{}",
                            size,
                            function_extent_source_name(extent->source),
                            extent->truncated ? " (limited)" : "");
                    }
                }
            } else if (model_.is_live_process()) {
                const GraphByteReader reader = [this](std::uint64_t offset, std::size_t length)
                    -> std::vector<std::uint8_t> {
                    if (const auto va = model_.offset_to_virtual_address(offset)) {
                        if (auto vbytes = model_.read_virtual_bytes(*va, length)) {
                            return std::move(*vbytes);
                        }
                    }
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
                    build_symbol_fanout_call_graph(*img, reader, symbol_index_, root),
                    "function_calls");
                if (current_call_graph_) {
                    call_graph_status_ = root.name + "  |  Calls";
                }
            } else {
                load_call_graph_from_graph(
                    build_symbol_fanout_call_graph(*img, model_.bytes(), symbol_index_, root),
                    "function_calls");
                if (current_call_graph_) {
                    call_graph_status_ = root.name + "  |  Calls";
                }
            }
        }
    }
}

void UiApp::load_call_graph_from_graph(CallGraph graph, const std::filesystem::path& output_name) {
    for (auto& node : graph.nodes) {
        if (node.bytes.start.virtual_address) {
            if (const auto* note = annotations_.find(*node.bytes.start.virtual_address); note && !note->name.empty())
                node.label = note->name;
        }
        for (auto& instruction : node.instructions) {
            if (const auto* note = annotations_.find(instruction.address); note && !note->comment.empty())
                instruction.operands += " ; " + note->comment.substr(0, 160);
            if (instruction.branch_target) {
                if (const auto* note = annotations_.find(*instruction.branch_target); note && !note->name.empty())
                    instruction.operands += " ; " + note->name;
            }
        }
    }
    // Add symbol annotations before layout so node widths include the names.
    for (auto& node : graph.nodes) for (auto& instruction : node.instructions) {
        if (!instruction.branch_target) continue;
        if (const auto* target = symbol_index_.find_containing_address(*instruction.branch_target);
            target && target->virtual_address) {
            const auto delta = *instruction.branch_target - *target->virtual_address;
            instruction.operands += delta ? std::format(" ; {}+0x{:X}", target->name, delta)
                                          : " ; " + target->name;
        }
    }
    current_call_graph_.reset();
    current_call_graph_layout_.reset();
    original_call_graph_layout_.reset();
    dragged_graph_card_.reset();
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
    original_call_graph_layout_ = current_call_graph_layout_;
    current_call_graph_ = std::move(graph);
    center_graph_selection_ = current_selection_.virtual_address.has_value();
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

    navigation_history_.visit(current_selection_);
    current_selection_ = selection_from_call_graph_node(node, *img);
    current_selection_.preferred_view = PreferredView::Graph;
    current_selection_.graph_root = active_graph_root_;
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

    if (node.kind == CallGraphNodeKind::BasicBlock) return;
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
            current_selection_.graph_root = resolved;
            pending_call_graph_root_ = std::move(resolved);
            pending_call_graph_delay_frames_ = 1;
            call_graph_status_ = "Queued fan-out from " + record->name;
        }
    }
}

void UiApp::render_call_graph_panel() {
    ImGui::SetNextWindowSize(ImVec2(900.0f, 420.0f), ImGuiCond_FirstUseEver);
    if (!ImGui::Begin("Flow Graph", &show_call_graph_panel_)) {
        ImGui::End();
        return;
    }
    if (ImGui::IsWindowFocused(ImGuiFocusedFlags_RootAndChildWindows) && !ImGui::GetIO().WantTextInput) {
        if (ImGui::IsKeyPressed(ImGuiKey_Space)) switch_analysis_view(false);
        if (current_call_graph_ && !current_call_graph_->nodes.empty()) {
            std::vector<const CallGraphNode*> nodes;
            for (const auto& node : current_call_graph_->nodes)
                if (node.bytes.start.virtual_address && node.bytes.start.file_offset) nodes.push_back(&node);
            auto selected = std::ranges::find_if(nodes, [this](const auto* node) {
                return current_selection_.virtual_address && *current_selection_.virtual_address >= *node->bytes.start.virtual_address &&
                    *current_selection_.virtual_address - *node->bytes.start.virtual_address < std::max<std::uint64_t>(1, node->bytes.size);
            });
            if (!nodes.empty() && (ImGui::IsKeyPressed(ImGuiKey_DownArrow) || ImGui::IsKeyPressed(ImGuiKey_UpArrow))) {
                auto index = selected == nodes.end() ? std::ptrdiff_t{0} : selected - nodes.begin();
                if (selected != nodes.end()) index += ImGui::IsKeyPressed(ImGuiKey_UpArrow) ? -1 : 1;
                index = std::clamp(index, std::ptrdiff_t{0}, static_cast<std::ptrdiff_t>(nodes.size() - 1));
                activate_call_graph_node(*nodes[static_cast<std::size_t>(index)]);
                center_graph_selection_ = true;
            }
            if (ImGui::IsKeyPressed(ImGuiKey_Enter) && selected != nodes.end()) {
                const auto target = std::ranges::find_if((*selected)->instructions, [](const auto& i) { return i.branch_target.has_value(); });
                if (target != (*selected)->instructions.end()) navigate_to_address(*target->branch_target, PreferredView::Graph);
            }
        }
    }

    if (ImGui::RadioButton("Control flow", function_cfg_)) {
        function_cfg_ = true; pending_call_graph_root_ = active_graph_root_;
    }
    ImGui::SameLine();
    if (ImGui::RadioButton("Calls", !function_cfg_)) {
        function_cfg_ = false; pending_call_graph_root_ = active_graph_root_;
    }
    ImGui::SameLine();
    if (ImGui::Button("Image overview")) {
        queue_call_graph_sample(CallGraphSample::LoadedImage);
    }
    ImGui::SameLine();
    if (ImGui::Button("Reload")) {
        if (active_graph_root_) pending_call_graph_root_ = active_graph_root_;
        else queue_call_graph_sample(call_graph_sample_);
    }
    ImGui::SameLine();
    if (ImGui::Button("Fit")) { fit_graph_ = true; graph_pan_ = {}; }
    ImGui::SameLine();
    if (ImGui::Button("100%")) { graph_zoom_ = 1; graph_pan_ = {}; }
    ImGui::SameLine();
    if (ImGui::Button("Reset cards") && original_call_graph_layout_) {
        current_call_graph_layout_ = original_call_graph_layout_;
        dragged_graph_card_.reset(); fit_graph_ = true; graph_pan_ = {};
    }
    ImGui::SameLine();
    ImGui::TextDisabled("Wheel: zoom  |  Middle-drag: pan  |  Drag: move card  |  Click: inspect");

    if (!call_graph_status_.empty()) {
        ImGui::TextUnformatted(call_graph_status_.c_str());
    }
    if (model_.image() != nullptr && reference_index_.total_executable_bytes() > 0) {
        const bool scanning = reference_index_.is_scanning() || reference_scanner_.is_scanning();
        ImGui::TextDisabled("Scan coverage: %.1f%% (%zu / %zu bytes%s)",
            reference_index_.coverage_percent(),
            reference_index_.scanned_bytes(),
            reference_index_.total_executable_bytes(),
            scanning ? ", scanning in background..." : (reference_index_.incomplete() ? ", budget capped" : ""));
        if (!scanning && reference_index_.incomplete()) {
            ImGui::SameLine();
            if (ImGui::SmallButton("Scan Full Binary##cfg_scan_full")) {
                if (reference_scanner_.has_resumable_work()) {
                    reference_scanner_.scan_full(reference_index_);
                }
            }
        }
    }
    if (current_call_graph_ && !current_call_graph_->indirect_recoveries.empty()) {
        const std::string header = std::format(
            "Indirect branch / call recovery ({} resolved)",
            current_call_graph_->indirect_recoveries.size());
        if (ImGui::TreeNode("IndirectRecoveries", "%s", header.c_str())) {
            for (std::size_t idx = 0; idx < current_call_graph_->indirect_recoveries.size(); ++idx) {
                const auto& rec = current_call_graph_->indirect_recoveries[idx];
                ImGui::PushID(static_cast<int>(idx));
                const std::string line = std::format(
                    "0x{:X} [{}] {}",
                    rec.source_address, rec.confidence, rec.evidence);
                if (ImGui::Selectable(line.c_str())) {
                    navigate_to_address(rec.source_address, PreferredView::Disassembly);
                }
                ImGui::PopID();
            }
            ImGui::TreePop();
        }
    }
    if (!current_call_graph_) ImGui::TextWrapped("Select a function in Functions & Names to explore its calls, or build the loaded-image graph.");

    ImGui::InputTextWithHint("Find node", "Any part of a function name...", graph_search_, sizeof(graph_search_));
    if (current_call_graph_ && current_call_graph_->id != "function_cfg" &&
        ImGui::CollapsingHeader("Callers / Callees (current graph)")) {
        ImGui::BeginChild("CallRelations", ImVec2(0, 160), true);
        for (const auto& root : current_call_graph_->nodes) {
            if (graph_search_[0] && !symbol_name_matches(root.label, graph_search_)) continue;
            ImGui::PushID(root.id.c_str());
            if (ImGui::TreeNode(root.label.c_str())) {
                for (const bool callers : {true, false}) {
                    if (ImGui::TreeNode(callers ? "Callers" : "Callees")) {
                        const auto ids = call_neighbors(*current_call_graph_, root.id, callers);
                        if (ids.empty()) ImGui::TextDisabled("No known calls in this graph");
                        for (const auto& id : ids) {
                            const auto node = std::ranges::find_if(current_call_graph_->nodes,
                                [&](const auto& candidate) { return candidate.id == id; });
                            if (node == current_call_graph_->nodes.end()) continue;
                            ImGui::PushID(id.c_str());
                            const auto label = node->label + (id == root.id ? " (recursive)" : "");
                            if (ImGui::Selectable(label.c_str())) activate_call_graph_node(*node);
                            ImGui::PopID();
                        }
                        ImGui::TreePop();
                    }
                }
                ImGui::TreePop();
            }
            ImGui::PopID();
        }
        ImGui::EndChild();
    }
    if (current_call_graph_ && graph_search_[0] != '\0') {
        ImGui::BeginChild("GraphSearchResults", ImVec2(0, 100), true);
        for (const auto& node : current_call_graph_->nodes) {
            if (!symbol_name_matches(node.label, graph_search_) &&
                (!node.symbol || (!symbol_name_matches(node.symbol->name, graph_search_) &&
                                  (node.symbol->demangled_name.empty() ||
                                   !symbol_name_matches(node.symbol->demangled_name, graph_search_))))) continue;
            ImGui::PushID(node.id.c_str());
            const std::string item_label =
                (model_.demangle_symbols() && node.symbol && !node.symbol->demangled_name.empty())
                    ? node.symbol->demangled_name
                    : node.label;
            if (ImGui::Selectable(item_label.c_str())) activate_call_graph_node(node);
            if (ImGui::IsItemHovered() && node.symbol && item_label != node.symbol->name) {
                ImGui::SetTooltip("Raw symbol: %s", node.symbol->name.c_str());
            }
            ImGui::PopID();
        }
        ImGui::EndChild();
    }
    const ImVec2 available = ImGui::GetContentRegionAvail();
    const ImVec2 canvas_size(std::max(available.x, 64.0f), std::max(available.y, 64.0f));
    const ImVec2 canvas_pos = ImGui::GetCursorScreenPos();
    if (ImGui::IsWindowHovered() && ImGui::IsMouseHoveringRect(canvas_pos, ImVec2(canvas_pos.x + canvas_size.x, canvas_pos.y + canvas_size.y))) {
        if (ImGui::GetIO().MouseWheel != 0)
            graph_zoom_ = std::clamp(graph_zoom_ * (1.0f + ImGui::GetIO().MouseWheel * 0.12f), 0.05f, 4.0f);
        if (ImGui::IsMouseDragging(ImGuiMouseButton_Middle)) {
            graph_pan_.x += ImGui::GetIO().MouseDelta.x;
            graph_pan_.y += ImGui::GetIO().MouseDelta.y;
        }
    }
    ImDrawList* draw_list = ImGui::GetWindowDrawList();
    draw_list->PushClipRect(canvas_pos, ImVec2(canvas_pos.x + canvas_size.x, canvas_pos.y + canvas_size.y), true);
    draw_list->AddRectFilled(canvas_pos,
                             ImVec2(canvas_pos.x + canvas_size.x, canvas_pos.y + canvas_size.y),
                             ImGui::GetColorU32(ImGuiCol_ChildBg));

    if (current_call_graph_ && current_call_graph_layout_) {
        const GraphLayoutBounds bounds = graph_layout_bounds(*current_call_graph_layout_);
        const float graph_width = static_cast<float>(std::max(1.0, bounds.max_x - bounds.min_x));
        const float graph_height = static_cast<float>(std::max(1.0, bounds.max_y - bounds.min_y));
        constexpr float kGraphPadding = 32.0f;
        const ImVec2 padded_canvas_size(std::max(1.0f, canvas_size.x - kGraphPadding * 2.0f),
                                        std::max(1.0f, canvas_size.y - kGraphPadding * 2.0f));
        const float native_scale = ImGui::GetFontSize() * 7.2f;
        if (fit_graph_) {
            graph_zoom_ = std::min({padded_canvas_size.x / graph_width,
                                   padded_canvas_size.y / graph_height, native_scale}) / native_scale;
            fit_graph_ = false;
        }
        const float scale = native_scale * graph_zoom_;
        const ImVec2 draw_size(std::max(1.0f, graph_width * scale), std::max(1.0f, graph_height * scale));
        if (center_graph_selection_) {
            for (const auto& node : current_call_graph_->nodes) {
                if (!node.bytes.start.virtual_address || !current_selection_.virtual_address) continue;
                const auto start = *node.bytes.start.virtual_address;
                const auto address = *current_selection_.virtual_address;
                if (address < start || address - start >= std::max<std::uint64_t>(1, node.bytes.size)) continue;
                const auto layout = std::ranges::find_if(current_call_graph_layout_->nodes,
                    [&](const auto& item) { return item.node_id == node.id; });
                if (layout != current_call_graph_layout_->nodes.end()) {
                    graph_pan_.x = draw_size.x * 0.5f - static_cast<float>(layout->center_x - bounds.min_x) * scale;
                    graph_pan_.y = canvas_size.y * 0.5f - kGraphPadding - static_cast<float>(bounds.max_y - layout->center_y) * scale;
                }
                break;
            }
            center_graph_selection_ = false;
        }
        const ImVec2 graph_pos(canvas_pos.x + (canvas_size.x - draw_size.x) * 0.5f + graph_pan_.x,
                               canvas_pos.y + kGraphPadding + graph_pan_.y);

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
            const bool cfg = current_call_graph_->id == "function_cfg";
            const auto start = to_screen(from->center_x + (cfg ? 0 : from->width / 2), from->center_y - (cfg ? from->height / 2 : 0));
            const auto end = to_screen(to->center_x - (cfg ? 0 : to->width / 2), to->center_y + (cfg ? to->height / 2 : 0));
            const auto color = ImGui::GetColorU32(edge.kind == CallGraphEdgeKind::ConditionalBranch ? ImGuiCol_PlotLines :
                edge.kind == CallGraphEdgeKind::Fallthrough ? ImGuiCol_PlotHistogramHovered : ImGuiCol_CheckMark);
            const float bend = std::max(24.0f, (cfg ? std::abs(end.y - start.y) : std::abs(end.x - start.x)) * 0.45f);
            draw_list->AddBezierCubic(start, ImVec2(start.x + (cfg ? 0 : bend), start.y + (cfg ? bend : 0)),
                ImVec2(end.x - (cfg ? 0 : bend), end.y - (cfg ? bend : 0)), end, color, 1.8f);
            if (cfg) draw_list->AddTriangleFilled(end, ImVec2(end.x - 5, end.y - 9), ImVec2(end.x + 5, end.y - 9), color);
            else draw_list->AddTriangleFilled(end, ImVec2(end.x - 9, end.y - 5), ImVec2(end.x - 9, end.y + 5), color);
            if (!edge.label.empty()) draw_list->AddText(ImGui::GetFont(), std::max(3.0f, scale / 7.2f),
                ImVec2((start.x + end.x) * 0.5f + 6, (start.y + end.y) * 0.5f), color, edge.label.c_str());
        }

        for (const GraphLayoutNode& layout_node : current_call_graph_layout_->nodes) {
            const auto graph_node = std::ranges::find_if(current_call_graph_->nodes, [&](const CallGraphNode& node) {
                return node.id == layout_node.node_id;
            });
            const std::string label = graph_node == current_call_graph_->nodes.end()
                                          ? layout_node.node_id
                                          : call_graph_node_display_label(*graph_node, model_.demangle_symbols());
            bool selected = false;
            const peelf::IBinaryImage* img = model_.image();
            if (graph_node != current_call_graph_->nodes.end() && img != nullptr) {
                selected = same_selection(current_selection_, selection_from_call_graph_node(*graph_node, *img));
                if (current_selection_.virtual_address && graph_node->bytes.start.virtual_address) {
                    const auto address = *current_selection_.virtual_address;
                    const auto start = *graph_node->bytes.start.virtual_address;
                    selected = address >= start && address - start < std::max<std::uint64_t>(graph_node->bytes.size, 1);
                    if (selected_code_address_ == current_selection_.virtual_address && decompile_revision_ == model_.edit_revision()) {
                        for (const auto& range : selected_code_ranges_)
                            if (range.address >= start && range.address-start < graph_node->bytes.size) selected = true;
                    }
                }
            }
            const ImVec2 top_left = to_screen(layout_node.center_x - layout_node.width * 0.5,
                                              layout_node.center_y + layout_node.height * 0.5);
            const ImVec2 bottom_right = to_screen(layout_node.center_x + layout_node.width * 0.5,
                                                  layout_node.center_y - layout_node.height * 0.5);
            draw_list->AddRectFilled(top_left,
                                     bottom_right,
                                     ImGui::GetColorU32(selected ? ImGuiCol_HeaderActive : ImGuiCol_FrameBg),
                                     4.0f);
            draw_list->AddRect(top_left,
                               bottom_right,
                               ImGui::GetColorU32(selected ? ImGuiCol_CheckMark : ImGuiCol_Border),
                               4.0f,
                               0,
                               selected ? 3.0f : 2.0f);
            const float font_size = std::max(3.0f, scale / 7.2f);
            draw_list->AddRectFilled(top_left, ImVec2(bottom_right.x, top_left.y + font_size + 10), ImGui::GetColorU32(ImGuiCol_Header), 4);
            draw_list->PushClipRect(top_left, bottom_right, true);
            draw_list->AddText(code_font_ ? code_font_ : ImGui::GetFont(), font_size,
                ImVec2(top_left.x + 8, top_left.y + 5), ImGui::GetColorU32(ImGuiCol_Text), label.c_str());
            draw_list->PopClipRect();
        }

        ImGui::SetCursorScreenPos(canvas_pos);
        ImGui::InvisibleButton("CallGraphVectorHitTarget", canvas_size);
        if (ImGui::IsItemClicked(ImGuiMouseButton_Left)) {
            if (const CallGraphNode* node =
                    hit_test_call_graph_node(graph_pos, scale, bounds.min_x, bounds.max_y, ImGui::GetIO().MousePos)) {
                if (ImGui::IsMouseDoubleClicked(ImGuiMouseButton_Left) && !node->instructions.empty()) {
                    const auto layout = std::ranges::find_if(current_call_graph_layout_->nodes,
                        [&](const auto& item) { return item.node_id == node->id; });
                    if (layout != current_call_graph_layout_->nodes.end()) {
                        const float top = to_screen(layout->center_x, layout->center_y + layout->height * 0.5).y + 5;
                        const auto row = static_cast<int>((ImGui::GetIO().MousePos.y - top) / std::max(3.0f, scale / 7.2f)) - 1;
                        if (row >= 0 && static_cast<std::size_t>(row) < node->instructions.size()) {
                            const auto target = node->instructions[static_cast<std::size_t>(row)].branch_target;
                            if (target) navigate_to_address(*target, PreferredView::Graph);
                        }
                    }
                } else {
                    dragged_graph_card_ = node->id;
                    graph_card_moved_ = false;
                    graph_card_mouse_ = ImGui::GetIO().MousePos;
                }
            }
        }
        if (dragged_graph_card_) {
            const auto mouse = ImGui::GetIO().MousePos;
            const ImVec2 delta(mouse.x - graph_card_mouse_.x, mouse.y - graph_card_mouse_.y);
            const auto threshold = ImGui::GetIO().MouseDragThreshold;
            if ((graph_card_moved_ || delta.x*delta.x + delta.y*delta.y >= threshold*threshold) &&
                move_graph_card(*current_call_graph_layout_, *dragged_graph_card_, delta.x, delta.y, scale)) {
                graph_card_moved_ = true;
                graph_card_mouse_ = mouse;
                const auto moved_bounds = graph_layout_bounds(*current_call_graph_layout_);
                // Changing the outer bounds must not move the other cards on screen.
                graph_pan_.x += static_cast<float>((moved_bounds.min_x + moved_bounds.max_x - bounds.min_x - bounds.max_x) * 0.5) * scale;
                graph_pan_.y += static_cast<float>(bounds.max_y - moved_bounds.max_y) * scale;
                ImGui::SetMouseCursor(ImGuiMouseCursor_ResizeAll);
            }
        }
        if (dragged_graph_card_ && !ImGui::IsMouseDown(ImGuiMouseButton_Left)) {
            if (!graph_card_moved_ && ImGui::IsItemHovered() && ImGui::IsMouseReleased(ImGuiMouseButton_Left)) {
                const auto node = std::ranges::find(current_call_graph_->nodes, *dragged_graph_card_, &CallGraphNode::id);
                if (node != current_call_graph_->nodes.end()) activate_call_graph_node(*node);
            }
            dragged_graph_card_.reset();
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
                           ImGui::GetColorU32(ImGuiCol_TextDisabled),
                           message);
    }

    draw_list->PopClipRect();
    ImGui::SetCursorScreenPos(canvas_pos);
    if (!call_graph_texture_) {
        ImGui::Dummy(canvas_size);
    } else {
        ImGui::SetCursorScreenPos(ImVec2(canvas_pos.x, canvas_pos.y + canvas_size.y));
    }
    ImGui::End();
}

void UiApp::build_default_dock_layout(ImGuiID dockspace_id, const ImVec2& dockspace_size) {
    focus_workspace_ = true;
    ImGui::DockBuilderRemoveNode(dockspace_id);
    ImGui::DockBuilderAddNode(dockspace_id, ImGuiDockNodeFlags_DockSpace);
    ImGui::DockBuilderSetNodeSize(dockspace_id, dockspace_size);

    ImGuiID main_id = dockspace_id;
    const bool compact = dockspace_size.x < ImGui::GetFontSize() * 100.0f;
    const ImGuiID bottom_id = ImGui::DockBuilderSplitNode(main_id, ImGuiDir_Down, 0.12f, nullptr, &main_id);
    const ImGuiID left_id = ImGui::DockBuilderSplitNode(main_id, ImGuiDir_Left, compact ? 0.25f : 0.19f, nullptr, &main_id);
    const ImGuiID right_id = compact ? left_id : ImGui::DockBuilderSplitNode(main_id, ImGuiDir_Right, 0.25f, nullptr, &main_id);
    const ImGuiID center_bottom_id = ImGui::DockBuilderSplitNode(main_id, ImGuiDir_Down, 0.26f, nullptr, &main_id);

    ImGui::DockBuilderDockWindow(structure_panel_.name().c_str(), left_id);
    ImGui::DockBuilderDockWindow(memory_map_panel_.name().c_str(), left_id);
    ImGui::DockBuilderDockWindow(functions_panel_.name().c_str(), left_id);
    ImGui::DockBuilderDockWindow(symbols_panel_.name().c_str(), left_id);
    ImGui::DockBuilderDockWindow(sections_panel_.name().c_str(), left_id);
    ImGui::DockBuilderDockWindow("Data Structures", left_id);

    ImGui::DockBuilderDockWindow(file_panel_.name().c_str(), right_id);
    ImGui::DockBuilderDockWindow(details_panel_.name().c_str(), right_id);
    ImGui::DockBuilderDockWindow(threads_panel_.name().c_str(), right_id);
    ImGui::DockBuilderDockWindow(thread_locals_panel_.name().c_str(), right_id);
    ImGui::DockBuilderDockWindow(runtime_flags_panel_.name().c_str(), right_id);
    ImGui::DockBuilderDockWindow(handlers_panel_.name().c_str(), right_id);
    ImGui::DockBuilderDockWindow(references_panel_.name().c_str(), right_id);
    ImGui::DockBuilderDockWindow(strings_panel_.name().c_str(), right_id);
    ImGui::DockBuilderDockWindow(struct_view_panel_.name().c_str(), right_id);
    ImGui::DockBuilderDockWindow(process_internals_panel_.name().c_str(), right_id);
    ImGui::DockBuilderDockWindow(imports_panel_.name().c_str(), right_id);
    ImGui::DockBuilderDockWindow(exports_panel_.name().c_str(), right_id);
    ImGui::DockBuilderDockWindow(patch_set_panel_.name().c_str(), right_id);
    ImGui::DockBuilderDockWindow(pe_headers_panel_.name().c_str(), right_id);
    ImGui::DockBuilderDockWindow(pe_imports_panel_.name().c_str(), right_id);
    ImGui::DockBuilderDockWindow(pe_exports_panel_.name().c_str(), right_id);

    ImGui::DockBuilderDockWindow(hex_panel_.name().c_str(), center_bottom_id);
    ImGui::DockBuilderDockWindow(memory_search_panel_.name().c_str(), center_bottom_id);
    ImGui::DockBuilderDockWindow(shellcode_panel_.name().c_str(), center_bottom_id);
    ImGui::DockBuilderDockWindow("Disassembly", main_id);
    ImGui::DockBuilderDockWindow("Flow Graph", main_id);
    ImGui::DockBuilderDockWindow("Decompiler", right_id);
    if (auto* node = ImGui::DockBuilderGetNode(left_id)) node->SelectedTabId = ImHashStr(functions_panel_.name().c_str());
    if (auto* node = ImGui::DockBuilderGetNode(right_id)) node->SelectedTabId = ImHashStr(details_panel_.name().c_str());
    ImGui::DockBuilderDockWindow(log_panel_.name().c_str(), bottom_id);

    ImGui::DockBuilderFinish(dockspace_id);
}

    void UiApp::render_disassembly_panel() {
    if (rendered_edit_revision_ != model_.edit_revision()) {
        rendered_edit_revision_ = model_.edit_revision();
        if (disassembly_location_)
            disassemble_at_offset(disassembly_location_->file_offset, disassembly_location_->address);
    }
    ImGui::Begin("Disassembly");
    std::optional<std::uint64_t> follow_target;
    std::optional<int> scroll_to_row;
    if (ImGui::IsWindowFocused(ImGuiFocusedFlags_RootAndChildWindows) && !ImGui::GetIO().WantTextInput) {
        if (ImGui::IsKeyPressed(ImGuiKey_Space)) switch_analysis_view(true);
        const auto selected = std::ranges::find_if(current_instructions_, [this](const auto& instruction) {
            return current_selection_.virtual_address == instruction.address;
        });
        if (selected != current_instructions_.end() && ImGui::IsKeyPressed(ImGuiKey_Enter)) follow_target = selected->branch_target;
        if (!current_instructions_.empty() && (ImGui::IsKeyPressed(ImGuiKey_DownArrow) || ImGui::IsKeyPressed(ImGuiKey_UpArrow))) {
            auto index = selected == current_instructions_.end() ? std::ptrdiff_t{0} : selected - current_instructions_.begin();
            if (selected != current_instructions_.end()) index += ImGui::IsKeyPressed(ImGuiKey_UpArrow) ? -1 : 1;
            index = std::clamp(index, std::ptrdiff_t{0}, static_cast<std::ptrdiff_t>(current_instructions_.size() - 1));
            const auto& instruction = current_instructions_[static_cast<std::size_t>(index)];
            if (const auto offset = model_.virtual_address_to_offset(instruction.address)) {
                const auto root = navigation_graph_root(instruction.address);
                current_selection_ = {.kind = SelectionKind::ByteRange, .label = instruction.to_string(),
                    .file_offset = *offset, .virtual_address = instruction.address, .size = instruction.bytes.size(),
                    .preferred_view = PreferredView::Disassembly, .graph_root = root};
                scroll_to_row = static_cast<int>(index);
                last_navigation_selection_ = current_selection_;
                hex_panel_.navigate_to_range(static_cast<std::size_t>(*offset), instruction.bytes.size());
            }
        }
    }

    if (!file_loaded_ || !disasm_.is_initialized()) {
        ImGui::TextDisabled("No file or live process loaded, or disassembler not initialized.");
        ImGui::End();
        return;
    }

    if (disasm_.architecture() == Architecture::ARM32 && ImGui::Checkbox("Thumb mode", &thumb_mode_)) {
        if (disasm_.set_thumb_mode(thumb_mode_)) {
            pending_call_graph_root_ = active_graph_root_;
            if (disassembly_location_)
                disassemble_at_offset(disassembly_location_->file_offset, disassembly_location_->address);
        } else {
            thumb_mode_ = !thumb_mode_;
            Log().error("Unable to change ARM instruction mode");
        }
    }
    if (!disasm_status_.empty()) ImGui::TextWrapped("%s", disasm_status_.c_str());
    // Simple table view
    if (ImGui::BeginTable("DisasmTableReadable", 5,
                          ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg |
                          ImGuiTableFlags_ScrollY | ImGuiTableFlags_ScrollX | ImGuiTableFlags_Resizable)) {
        ImGui::TableSetupColumn("Address", ImGuiTableColumnFlags_WidthFixed | ImGuiTableColumnFlags_NoResize, ImGui::CalcTextSize("0000000000000000").x + 16.0f);
        ImGui::TableSetupColumn("Bytes", ImGuiTableColumnFlags_WidthFixed, 180.0f);
        ImGui::TableSetupColumn("Mnemonic", ImGuiTableColumnFlags_WidthFixed, 80.0f);
        ImGui::TableSetupColumn("Operands", ImGuiTableColumnFlags_WidthFixed, ImGui::GetFontSize() * 22.0f);
        ImGui::TableSetupColumn("Symbol / annotation", ImGuiTableColumnFlags_WidthFixed, ImGui::GetFontSize() * 28.0f);
        ImGui::TableSetupScrollFreeze(1, 1);
        ImGui::TableHeadersRow();

        ImGuiListClipper clipper;
        clipper.Begin(static_cast<int>(current_instructions_.size()));
        if (scroll_to_row) clipper.IncludeItemByIndex(*scroll_to_row);
        while (clipper.Step()) {
        for (int row = clipper.DisplayStart; row < clipper.DisplayEnd; ++row) {
            const auto& inst = current_instructions_[static_cast<std::size_t>(row)];
            ImGui::TableNextRow();

            // Address
            ImGui::TableNextColumn();
            ImGui::PushID(row);
            if (ImGui::Selectable(std::format("{:016X}", inst.address).c_str(),
                current_selection_.virtual_address == inst.address, ImGuiSelectableFlags_AllowDoubleClick)) {
                if (ImGui::IsMouseDoubleClicked(ImGuiMouseButton_Left)) follow_target = inst.branch_target;
                if (const auto offset = model_.virtual_address_to_offset(inst.address)) {
                    const auto root = navigation_graph_root(inst.address);
                    hex_panel_.navigate_to_range(static_cast<std::size_t>(*offset), inst.bytes.size());
                    current_selection_ = ViewerSelection{
                        .kind = SelectionKind::ByteRange,
                        .label = "Instruction: " + inst.to_string(),
                        .file_offset = *offset,
                        .virtual_address = inst.address,
                        .size = inst.bytes.size(),
                        .preferred_view = PreferredView::Disassembly,
                        .graph_root = root
                    };
                    last_navigation_selection_ = current_selection_;
                }
            }
            ImGui::PopID();

            // Bytes
            if (scroll_to_row && row == *scroll_to_row) ImGui::SetScrollHereY();
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
            if (inst.branch_target) {
                const auto* target = symbol_index_.find_containing_address(*inst.branch_target);
                if (target && target->virtual_address) {
                    const auto delta = *inst.branch_target - *target->virtual_address;
                    const std::string& tname = target->display_name(model_.demangle_symbols());
                    const auto label = delta ? std::format("{}+0x{:X}", tname, delta) : tname;
                    ImGui::SameLine();
                    ImGui::TextDisabled("; %s", label.c_str());
                    if (ImGui::IsItemHovered() && tname != target->name) {
                        ImGui::SetTooltip("Raw symbol: %s", target->name.c_str());
                    }
                }
            }
            ImGui::TableNextColumn();
            const SourceLineMapping* exact_src = model_.find_source_line(inst.address, 0);
            const SourceLineMapping* near_src = exact_src != nullptr
                ? exact_src
                : model_.find_source_line(inst.address, 32);
            std::string col_text;
            std::string raw_tooltip;
            if (const auto* note = annotations_.find(inst.address); note && (!note->name.empty() || !note->comment.empty())) {
                col_text = note->name + (note->comment.empty() ? "" : " ; " + note->comment);
            } else if (const auto* symbol = symbol_index_.find_containing_address(inst.address); symbol && symbol->virtual_address) {
                const auto offset = inst.address - *symbol->virtual_address;
                const std::string& sname = symbol->display_name(model_.demangle_symbols());
                col_text = offset == 0 ? sname : std::format("{}+0x{:X}", sname, offset);
                if (sname != symbol->name) {
                    raw_tooltip = symbol->name;
                }
            }
            if (exact_src != nullptr) {
                const std::string src_tag = std::format("[{}:{}]",
                    !exact_src->file_name.empty() ? exact_src->file_name : exact_src->file_path,
                    exact_src->line);
                col_text = col_text.empty() ? src_tag : (col_text + "  " + src_tag);
            }
            if (!col_text.empty()) {
                ImGui::TextUnformatted(col_text.c_str());
                if (ImGui::IsItemHovered() && (!raw_tooltip.empty() || near_src != nullptr)) {
                    if (!raw_tooltip.empty() && near_src != nullptr) {
                        ImGui::SetTooltip("Raw symbol: %s\nSource: %s:%u",
                                          raw_tooltip.c_str(), near_src->file_path.c_str(), near_src->line);
                    } else if (!raw_tooltip.empty()) {
                        ImGui::SetTooltip("Raw symbol: %s", raw_tooltip.c_str());
                    } else if (near_src != nullptr) {
                        ImGui::SetTooltip("Source: %s:%u", near_src->file_path.c_str(), near_src->line);
                    }
                }
            }
        }
        }

        ImGui::EndTable();
                          }

    ImGui::End();
    if (follow_target) navigate_to_address(*follow_target);
}

    void UiApp::sync_live_process_view(bool navigate_to_entry) {
        if (!model_.is_live_process() || model_.process_session() == nullptr) {
            return;
        }

        symbol_index_ = model_.symbol_index();
        debug_types_.assign(model_.debug_types().begin(), model_.debug_types().end());
        ++symbol_revision_;
        strings_dirty_ = true;
        references_dirty_ = true;
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
        struct_view_panel_.reset_for_new_binary();
        Log().info("Attached to PID {} ({}): {} regions, {} modules, {} symbols",
                   model_.process_session()->pid(),
                   model_.process_session()->info().name,
                   model_.memory_regions().size(),
                   model_.process_modules().size(),
                   model_.symbol_index().size());
    }

    // Called after a file (PE or ELF) is loaded into the model, or after detaching.
    void UiApp::on_file_loaded() {
        patch_set_panel_.reset_preview();
        decompile_stop_.request_stop(); ++file_generation_; decompiled_ = {};
        annotations_.clear();
        debug_types_.clear(); ++symbol_revision_; decompiled_root_.reset();
        selected_code_ranges_.clear(); selected_code_address_.reset();
        reference_scanner_.cancel(&reference_index_);
        reference_index_ = {};
        references_dirty_ = true;
        strings_index_.clear();
        strings_dirty_ = true;
        strings_panel_.reset_selection();
        struct_view_panel_.reset_for_new_binary();
        navigation_history_.clear();
        disassembly_location_.reset();
        thumb_mode_ = false;
        if (model_.is_live_process()) {
            on_process_attached();
            return;
        }

        const peelf::IBinaryImage* img = model_.image();
        if (!img) {
            symbol_index_ = {};
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
        recent_binaries_.remember(model_.file_info().path);
        if (!recent_binaries_.save(recent_binaries_path_)) Log().error("Could not save recent binary history");
        symbol_index_ = model_.symbol_index();
        debug_types_.assign(model_.debug_types().begin(), model_.debug_types().end());
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
        Log().info("Loaded {} symbol records ({} debug types, {} source lines)",
                   model_.symbol_index().size(),
                   model_.debug_types().size(),
                   model_.source_lines().size());

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

        // Keep legacy metadata for PE-only tools, but decode both formats from
        // the same effective-byte source used by the hex editor.
        if (const PeModel* pe = model_.pe()) {
            pe_model_ = *pe;
        }
        if (const auto entry_offset = img->virtual_address_to_file_offset(img->entry_point())) {
            disassemble_at_offset(static_cast<std::size_t>(*entry_offset), img->entry_point());
        }

        call_graph_sample_ = CallGraphSample::LoadedImage;
        active_graph_root_.reset();
        if (const auto offset = img->virtual_address_to_file_offset(img->entry_point())) {
            const auto* symbol = symbol_index_.find_containing_address(img->entry_point());
            pending_call_graph_root_ = symbol ? *symbol : SymbolRecord{.name = "Entry point", .virtual_address = img->entry_point(), .file_offset = *offset};
            function_cfg_ = true;
            show_call_graph_panel_ = true;
            focus_graph_ = true;
        }
        call_graph_status_ = "Analyzing entry point";
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

        DebugSymbolLoadResult result = load_debug_symbols_file(path, *img);
        if (result.status != DebugSymbolLoadStatus::Loaded) {
            Log().warn("Debug symbols not loaded ({}): {}",
                       to_string(result.status),
                       result.diagnostic);
            return;
        }

        model_.apply_debug_symbol_result(result);
        symbol_index_ = model_.symbol_index();
        debug_types_.assign(model_.debug_types().begin(), model_.debug_types().end());
        ++symbol_revision_;
        Log().info("Loaded {} debug symbols, {} types, and {} source lines from {}; symbol index now has {} records",
                   result.symbols.size(),
                   result.types.size(),
                   result.lines.size(),
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


std::optional<SymbolRecord> UiApp::navigation_graph_root(std::uint64_t address) const {
    if (current_selection_.virtual_address == address && current_selection_.graph_root)
        return current_selection_.graph_root;
    if (active_graph_root_ && current_call_graph_ && current_call_graph_->id == "function_cfg") {
        for (const auto& node : current_call_graph_->nodes) {
            if (node.kind != CallGraphNodeKind::BasicBlock || !node.bytes.start.virtual_address) continue;
            const auto start = *node.bytes.start.virtual_address;
            if (address >= start && address - start < node.bytes.size) return active_graph_root_;
        }
    }
    if (const auto* image = model_.image()) {
        if (const auto* symbol = symbol_index_.find_containing_address(address); symbol && symbol_has_code(*image, *symbol))
            return *symbol;
    }
    return std::nullopt;
}

void UiApp::navigate_to_address(std::uint64_t address, PreferredView view) {
    if (!model_.has_file()) {
        return;
    }

    std::optional<std::uint64_t> offset = model_.virtual_address_to_offset(address);
    if (!offset && model_.is_live_process()) {
        if (model_.navigate_to_virtual_address(address)) {
            sync_live_process_view(false);
            offset = model_.virtual_address_to_offset(address);
        }
    }
    if (!offset || *offset >= model_.view_size()) {
        Log().warn("Address 0x{:X} is not mapped in the active image or memory map", address);
        return;
    }

    navigation_history_.visit(current_selection_);
    const auto* symbol = symbol_index_.find_containing_address(address);
    auto root = navigation_graph_root(address);
    const std::optional<std::uint64_t> static_file_off =
        model_.image() != nullptr ? model_.image()->virtual_address_to_file_offset(address) : offset;
    if (!root) {
        root = SymbolRecord{
            .name = std::format("loc_{:X}", address),
            .virtual_address = address,
            .file_offset = static_file_off.value_or(*offset),
        };
    }
    current_selection_ = {
        .kind = SelectionKind::ByteRange,
        .label = symbol ? symbol->name : std::format("loc_{:X}", address),
        .file_offset = *offset,
        .virtual_address = address,
        .size = 1,
        .preferred_view = view,
        .graph_root = root,
    };
    hex_panel_.navigate_to_range(clamp_to_size_t(*offset), 1);
    disassemble_at_offset(*offset, address);
    last_navigation_selection_ = current_selection_;
    if (view == PreferredView::Graph && model_.image() != nullptr) {
        if (!active_graph_root_ || active_graph_root_->virtual_address != root->virtual_address) {
            pending_call_graph_root_ = *root;
            pending_call_graph_delay_frames_ = 0;
        }
        show_call_graph_panel_ = true;
        focus_graph_ = true;
        center_graph_selection_ = true;
    } else if (view == PreferredView::Hex) {
        hex_panel_.set_visible(true);
        activate_panel("Hex View");
    } else {
        show_disassembly_panel_ = true;
        focus_listing_ = true;
    }
    navigation_history_.visit(current_selection_);
}

void UiApp::navigate_history(bool forward) {
    navigation_history_.visit(current_selection_);
    const auto destination = forward ? navigation_history_.forward() : navigation_history_.back();
    if (!destination) return;
    // Set the destination first so the common navigation path preserves the cursor.
    current_selection_ = *destination;
    if (destination->virtual_address) {
        navigate_to_address(*destination->virtual_address, destination->preferred_view);
        current_selection_ = *destination;
        last_navigation_selection_ = current_selection_;
        if (destination->file_offset) hex_panel_.navigate_to_range(static_cast<std::size_t>(*destination->file_offset),
            static_cast<std::size_t>(std::max<std::uint64_t>(1, destination->size)));
    }
    else { last_navigation_selection_.reset(); apply_structure_selection_navigation(); }
}

void UiApp::switch_analysis_view(bool graph) {
    auto selection = current_selection_;
    if (current_selection_.virtual_address) {
        navigate_to_address(*current_selection_.virtual_address, graph ? PreferredView::Graph : PreferredView::Disassembly);
        selection.graph_root = current_selection_.graph_root;
        selection.preferred_view = graph ? PreferredView::Graph : PreferredView::Disassembly;
        current_selection_ = std::move(selection);
        last_navigation_selection_ = current_selection_;
        if (current_selection_.file_offset) hex_panel_.navigate_to_range(static_cast<std::size_t>(*current_selection_.file_offset),
            static_cast<std::size_t>(std::max<std::uint64_t>(1, current_selection_.size)));
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
                        const auto disasm_win = static_cast<std::size_t>(
                            std::clamp<std::uint64_t>(reg_copy.size(), 4096u, 65536u));
                        disassemble_at_offset(off, reg_copy.start_address, disasm_win);
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
        disassemble_at_offset(file_offset, display_address, 4096u);
    }

    void UiApp::disassemble_at_offset(std::uint64_t file_offset, std::uint64_t display_address) {
        disassemble_at_offset(file_offset, display_address, 4096u);
    }

    void UiApp::disassemble_at_offset(std::uint64_t file_offset,
                                      std::uint64_t display_address,
                                      std::size_t max_window_bytes) {
        disassembly_location_ = DisassemblyLocation{clamp_to_size_t(file_offset), display_address};
        if (!file_loaded_ || !disasm_.is_initialized()) {
            return;
        }
        const std::uint64_t total_size = model_.view_size();
        if (file_offset >= total_size) {
            return;
        }
        last_disasm_offset_ = file_offset;
        last_disasm_address_ = display_address;
        last_disasm_window_ = std::clamp<std::size_t>(max_window_bytes, 256u, 65536u);

        const auto sample = model_.read_window_sample(file_offset, last_disasm_window_);
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
            disassemble_at_offset(*last_disasm_offset_, last_disasm_address_, last_disasm_window_);
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

        Log().info("Entry Point: 0x{:X}", va);
        printf("----------------------------------------\n");

        for (const auto& inst : current_instructions_) {
            std::string bytes_str;
            for (std::uint8_t b : inst.bytes) {
                char buf[4];
                snprintf(buf, sizeof(buf), "%02X ", b);
                bytes_str += buf;
            }

            Log().info("{:016X}  {:24}  {}",
                   inst.address,
                   bytes_str.c_str(),
                   inst.to_string().c_str());
        }
    }

    ImVec4 UiApp::get_mnemonic_color(const std::string& mnemonic) const {
    if (mnemonic.empty()) {
        return ImGui::GetStyleColorVec4(ImGuiCol_Text);
    }

    // Branch/control flow - Blue
    if (mnemonic[0] == 'j' ||
        mnemonic == "call" || mnemonic == "ret" || mnemonic == "retn" ||
        mnemonic == "loop" || mnemonic == "loope" || mnemonic == "loopne" ||
        mnemonic == "syscall" || mnemonic == "sysret" ||
        mnemonic == "b" || mnemonic == "bl" || mnemonic == "bx" || mnemonic == "blx" ||
        mnemonic == "cbz" || mnemonic == "cbnz") {
        return ImGui::GetStyleColorVec4(ImGuiCol_CheckMark);
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
        return ImGui::GetStyleColorVec4(ImGuiCol_PlotLines);
    }

    // NOP/padding - Gray
    if (mnemonic == "nop" || mnemonic == "int3" || mnemonic == "ud2") {
        return ImGui::GetStyleColorVec4(ImGuiCol_TextDisabled);
    }

    // Data movement - Light yellow
    if (mnemonic.find("mov") == 0 || mnemonic == "lea" ||
        mnemonic == "push" || mnemonic == "pop" ||
        mnemonic == "xchg" || mnemonic == "ldr" || mnemonic == "str") {
        return ImGui::GetStyleColorVec4(ImGuiCol_Text);
    }

    // Arithmetic - Orange
    if (mnemonic == "add" || mnemonic == "sub" || mnemonic == "mul" ||
        mnemonic == "div" || mnemonic == "inc" || mnemonic == "dec" ||
        mnemonic == "imul" || mnemonic == "idiv" || mnemonic == "neg") {
        return ImGui::GetStyleColorVec4(ImGuiCol_PlotHistogram);
    }

    // Logic/bitwise - Purple
    if (mnemonic == "and" || mnemonic == "or" || mnemonic == "xor" ||
        mnemonic == "not" || mnemonic == "shl" || mnemonic == "shr" ||
        mnemonic == "sar" || mnemonic == "rol" || mnemonic == "ror" ||
        mnemonic == "test" || mnemonic == "cmp") {
        return ImGui::GetStyleColorVec4(ImGuiCol_CheckMark);
    }

    // Compare/test - Cyan
    if (mnemonic == "cmp" || mnemonic == "test" ||
        mnemonic.find("cmp") == 0 || mnemonic.find("test") == 0) {
        return ImGui::GetStyleColorVec4(ImGuiCol_PlotLines);
    }

    // Default - White
    return ImGui::GetStyleColorVec4(ImGuiCol_Text);
}
} // namespace viewe
