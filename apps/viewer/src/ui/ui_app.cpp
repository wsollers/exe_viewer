#include "ui_app.hpp"
#include <imgui.h>
#include <imgui_internal.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <limits>
#include <optional>
#include <span>
#include <string>
#include <utility>
#include <vector>

#include "graph/call_graph.hpp"
#include "logger.hpp"

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
           lhs.label == rhs.label;
}

struct BmpImage {
    std::uint32_t width = 0;
    std::uint32_t height = 0;
    std::vector<std::uint8_t> rgba;
};

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

[[nodiscard]] std::optional<BmpImage> load_bmp_rgba(const std::filesystem::path& path) {
    std::ifstream file(path, std::ios::binary);
    if (!file) {
        return std::nullopt;
    }
    std::vector<std::uint8_t> bytes{std::istreambuf_iterator<char>(file), std::istreambuf_iterator<char>()};
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
    , structure_panel_(structure_tree_, current_selection_)
    , details_panel_(current_selection_)
    , sections_panel_(model)
    , hex_panel_(model)
    , imports_panel_(model)
    , exports_panel_(model)
    , symbols_panel_(model)
    , log_panel_()
    , pe_headers_panel_(model)
    , pe_imports_panel_(model)
    , pe_exports_panel_(model)
{
    hex_panel_.set_byte_activated_callback([this](std::size_t off) {
        disassemble_at_offset(off);
    });
    sections_panel_.set_section_activated_callback(
        [this](const peelf::Section& section, std::uint64_t object_index) {
            const std::uint64_t range_size = section.file_size != 0 ? section.file_size : section.virtual_size;
            current_selection_ = ViewerSelection{
                .kind = SelectionKind::Section,
                .label = section.name,
                .file_offset = section.file_offset,
                .virtual_address = section.virtual_address,
                .size = std::max(section.file_size, section.virtual_size),
                .object_index = object_index,
                .preferred_view = section.executable ? PreferredView::Disassembly : PreferredView::Hex
            };
            hex_panel_.navigate_to_range(static_cast<std::size_t>(section.file_offset),
                                         static_cast<std::size_t>(range_size));
            if (section.executable) {
                disassemble_at_offset(static_cast<std::size_t>(section.file_offset), section.virtual_address);
            }
            last_navigation_selection_ = current_selection_;
        });
    symbols_panel_.set_symbol_activated_callback([this](const peelf::Symbol& symbol, std::uint64_t object_index) {
        const peelf::IBinaryImage* img = model_.image();
        if (img == nullptr) {
            return;
        }

        const auto file_offset = img->virtual_address_to_file_offset(symbol.virtual_address);
        if (!file_offset) {
            Log().warn("Symbol '{}' at 0x{:X} does not map to file bytes",
                       symbol.name.empty() ? "<unnamed>" : symbol.name,
                       symbol.virtual_address);
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
            .preferred_view = PreferredView::Disassembly
        };
        hex_panel_.navigate_to_range(static_cast<std::size_t>(*file_offset), highlight_size);
        disassemble_at_offset(static_cast<std::size_t>(*file_offset), symbol.virtual_address);
        last_navigation_selection_ = current_selection_;
    });
    imports_panel_.set_import_activated_callback([this](const peelf::ImportEntry& entry, std::uint64_t object_index) {
        const peelf::IBinaryImage* img = model_.image();
        if (img == nullptr || entry.address == 0) {
            return;
        }

        const auto file_offset = img->virtual_address_to_file_offset(entry.address);
        if (!file_offset) {
            Log().warn("Import '{}!{}' at 0x{:X} does not map to file bytes",
                       entry.library,
                       entry.name.empty() ? "<ordinal-or-library>" : entry.name,
                       entry.address);
            return;
        }
        if (*file_offset > static_cast<std::uint64_t>(std::numeric_limits<std::size_t>::max())) {
            Log().warn("Import '{}!{}' address is too large for this platform",
                       entry.library,
                       entry.name.empty() ? "<ordinal-or-library>" : entry.name);
            return;
        }

        const std::size_t pointer_size = img->is_64bit() ? 8u : 4u;
        std::string label = entry.library;
        if (!entry.name.empty()) {
            label += "!";
            label += entry.name;
        }
        current_selection_ = ViewerSelection{
            .kind = SelectionKind::Import,
            .label = std::move(label),
            .file_offset = *file_offset,
            .virtual_address = entry.address,
            .size = pointer_size,
            .object_index = object_index,
            .preferred_view = PreferredView::Hex
        };
        hex_panel_.navigate_to_range(static_cast<std::size_t>(*file_offset), pointer_size);
        last_navigation_selection_ = current_selection_;
    });
    exports_panel_.set_export_activated_callback([this](const peelf::ExportEntry& entry, std::uint64_t object_index) {
        const peelf::IBinaryImage* img = model_.image();
        if (img == nullptr || entry.virtual_address == 0) {
            return;
        }

        const auto file_offset = img->virtual_address_to_file_offset(entry.virtual_address);
        if (!file_offset) {
            Log().warn("Export '{}' at 0x{:X} does not map to file bytes",
                       entry.name.empty() ? "<unnamed>" : entry.name,
                       entry.virtual_address);
            return;
        }
        if (*file_offset > static_cast<std::uint64_t>(std::numeric_limits<std::size_t>::max())) {
            Log().warn("Export '{}' address is too large for this platform",
                       entry.name.empty() ? "<unnamed>" : entry.name);
            return;
        }

        current_selection_ = ViewerSelection{
            .kind = SelectionKind::Export,
            .label = entry.name.empty() ? "<unnamed>" : entry.name,
            .file_offset = *file_offset,
            .virtual_address = entry.virtual_address,
            .size = 1,
            .object_index = object_index,
            .preferred_view = PreferredView::Disassembly
        };
        hex_panel_.navigate_to_range(static_cast<std::size_t>(*file_offset), 1);
        disassemble_at_offset(static_cast<std::size_t>(*file_offset), entry.virtual_address);
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

    file_panel_.draw();
    structure_panel_.draw();
    apply_structure_selection_navigation();
    details_panel_.draw();
    sections_panel_.draw();
    hex_panel_.draw();
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
            if (ImGui::MenuItem("Call Graph", nullptr, &show_call_graph_panel_)) {
                if (show_call_graph_panel_ && !call_graph_texture_) {
                    load_call_graph_sample(call_graph_sample_);
                }
            }
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

void UiApp::load_call_graph_sample(CallGraphSample sample) {
    if (sample == CallGraphSample::LoadedImage) {
        const peelf::IBinaryImage* image = model_.image();
        if (image == nullptr) {
            call_graph_status_ = "No image loaded. Open a PE/ELF file or choose a sample graph.";
            return;
        }
        load_call_graph_from_graph(build_entry_call_graph(*image), graph_bmp_name(sample));
        call_graph_sample_ = sample;
        return;
    }

    const std::optional<std::filesystem::path> graphs_dir = find_graphs_dir();
    if (!graphs_dir) {
        call_graph_status_ = "Could not find out/graphs. Generate the sample DOT files first.";
        return;
    }

    const std::filesystem::path dot_path = *graphs_dir / graph_dot_name(sample);
    const std::filesystem::path bmp_path = std::filesystem::temp_directory_path() / graph_bmp_name(sample);
    if (!std::filesystem::exists(dot_path)) {
        call_graph_status_ = "Missing DOT file: " + dot_path.string();
        return;
    }

    const DefaultProcessRunner runner;
    const GraphRenderCommand command =
        make_graphviz_render_command(dot_path, bmp_path, GraphRenderFormat::Bmp);
    const GraphRenderResult render_result = runner.run(command.executable, command.arguments);
    if (!render_result.success) {
        call_graph_status_ = "Graphviz failed to render BMP: " + render_result.diagnostic;
        return;
    }

    const std::optional<BmpImage> bmp = load_bmp_rgba(bmp_path);
    if (!bmp) {
        call_graph_status_ = "Failed to load BMP: " + bmp_path.string();
        return;
    }

    if (call_graph_texture_) {
        vulkan_.destroy_texture(*call_graph_texture_);
        call_graph_texture_.reset();
    }

    call_graph_texture_ = vulkan_.create_rgba_texture(std::span<const std::uint8_t>(bmp->rgba.data(), bmp->rgba.size()),
                                                      bmp->width,
                                                      bmp->height);
    loaded_call_graph_bmp_ = bmp_path;
    call_graph_sample_ = sample;
    call_graph_status_ = "Loaded " + bmp_path.filename().string();
}

void UiApp::load_call_graph_from_graph(const CallGraph& graph, const std::filesystem::path& output_name) {
    const std::filesystem::path bmp_path = std::filesystem::temp_directory_path() / output_name;
    const DefaultProcessRunner runner;
    const GraphRenderResult render_result =
        render_graph_with_graphviz(graph, bmp_path, GraphRenderFormat::Bmp, runner);
    if (!render_result.success) {
        call_graph_status_ = "Graphviz failed to render loaded-image graph: " + render_result.diagnostic;
        return;
    }

    const std::optional<BmpImage> bmp = load_bmp_rgba(bmp_path);
    if (!bmp) {
        call_graph_status_ = "Failed to load rendered graph BMP: " + bmp_path.string();
        return;
    }

    if (call_graph_texture_) {
        vulkan_.destroy_texture(*call_graph_texture_);
        call_graph_texture_.reset();
    }

    call_graph_texture_ = vulkan_.create_rgba_texture(std::span<const std::uint8_t>(bmp->rgba.data(), bmp->rgba.size()),
                                                      bmp->width,
                                                      bmp->height);
    loaded_call_graph_bmp_ = bmp_path;
    call_graph_status_ = "Loaded graph from current image";
}

void UiApp::render_call_graph_panel() {
    ImGui::SetNextWindowSize(ImVec2(900.0f, 420.0f), ImGuiCond_FirstUseEver);
    if (!ImGui::Begin("Call Graph", &show_call_graph_panel_)) {
        ImGui::End();
        return;
    }

    if (ImGui::Button("Loaded Image")) {
        load_call_graph_sample(CallGraphSample::LoadedImage);
    }
    ImGui::SameLine();
    if (ImGui::Button("PE x64 sample")) {
        load_call_graph_sample(CallGraphSample::PeStartup);
    }
    ImGui::SameLine();
    if (ImGui::Button("Linux ELF sample")) {
        load_call_graph_sample(CallGraphSample::ElfStartup);
    }
    ImGui::SameLine();
    if (ImGui::Button("Reload")) {
        load_call_graph_sample(call_graph_sample_);
    }

    if (!call_graph_status_.empty()) {
        ImGui::TextUnformatted(call_graph_status_.c_str());
    }

    if (!call_graph_texture_) {
        load_call_graph_sample(call_graph_sample_);
    }

    const ImVec2 available = ImGui::GetContentRegionAvail();
    const ImVec2 canvas_size(std::max(available.x, 64.0f), std::max(available.y, 64.0f));
    const ImVec2 canvas_pos = ImGui::GetCursorScreenPos();
    ImDrawList* draw_list = ImGui::GetWindowDrawList();
    draw_list->AddRectFilled(canvas_pos,
                             ImVec2(canvas_pos.x + canvas_size.x, canvas_pos.y + canvas_size.y),
                             IM_COL32(255, 255, 255, 255));

    if (call_graph_texture_) {
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
    } else {
        const char* message = "Call graph image unavailable";
        const ImVec2 text_size = ImGui::CalcTextSize(message);
        draw_list->AddText(ImVec2(canvas_pos.x + (canvas_size.x - text_size.x) * 0.5f,
                                  canvas_pos.y + (canvas_size.y - text_size.y) * 0.5f),
                           IM_COL32(80, 80, 80, 255),
                           message);
    }

    ImGui::Dummy(canvas_size);
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
    ImGui::DockBuilderDockWindow(file_panel_.name().c_str(), left_id);
    ImGui::DockBuilderDockWindow(sections_panel_.name().c_str(), left_id);
    ImGui::DockBuilderDockWindow(symbols_panel_.name().c_str(), left_id);

    ImGui::DockBuilderDockWindow(details_panel_.name().c_str(), right_id);
    ImGui::DockBuilderDockWindow(imports_panel_.name().c_str(), right_id);
    ImGui::DockBuilderDockWindow(exports_panel_.name().c_str(), right_id);
    ImGui::DockBuilderDockWindow(pe_headers_panel_.name().c_str(), right_id);
    ImGui::DockBuilderDockWindow(pe_imports_panel_.name().c_str(), right_id);
    ImGui::DockBuilderDockWindow(pe_exports_panel_.name().c_str(), right_id);

    ImGui::DockBuilderDockWindow(hex_panel_.name().c_str(), main_id);
    ImGui::DockBuilderDockWindow("Disassembly", center_bottom_id);
    ImGui::DockBuilderDockWindow(log_panel_.name().c_str(), bottom_id);

    ImGui::DockBuilderFinish(dockspace_id);
}

    void UiApp::render_disassembly_panel() {
    ImGui::Begin("Disassembly");


    if (!file_loaded_ || !disasm_.is_initialized()) {
        ImGui::Text("No file loaded or disassembler not initialized");
        ImGui::End();
        return;
    }

    // Simple table view
    if (ImGui::BeginTable("DisasmTable", 4,
                          ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg |
                          ImGuiTableFlags_ScrollY | ImGuiTableFlags_Resizable)) {
        ImGui::TableSetupColumn("Address", ImGuiTableColumnFlags_WidthFixed, 120.0f);
        ImGui::TableSetupColumn("Bytes", ImGuiTableColumnFlags_WidthFixed, 180.0f);
        ImGui::TableSetupColumn("Mnemonic", ImGuiTableColumnFlags_WidthFixed, 80.0f);
        ImGui::TableSetupColumn("Operands", ImGuiTableColumnFlags_WidthStretch);
        ImGui::TableHeadersRow();

        for (const auto &inst: current_instructions_) {
            ImGui::TableNextRow();

            // Address
            ImGui::TableNextColumn();
            ImGui::Text("%016llX", inst.address);

            // Bytes
            ImGui::TableNextColumn();
            std::string bytes_str;
            for (std::uint8_t b: inst.bytes) {
                char buf[4];
                snprintf(buf, sizeof(buf), "%02X ", b);
                bytes_str += buf;
            }
            ImGui::TextDisabled("%s", bytes_str.c_str());

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
    // Called after a file (PE or ELF) is loaded into the model.
    void UiApp::on_file_loaded() {
        const peelf::IBinaryImage* img = model_.image();
        if (!img) {
            file_loaded_ = false;
            structure_tree_.reset();
            symbol_index_ = {};
            current_selection_ = {};
            last_navigation_selection_.reset();
            return;
        }

        structure_tree_ = build_structure_tree(*img);
        symbol_index_ = SymbolIndex::build(*img);
        current_selection_ = structure_tree_->selection;
        last_navigation_selection_.reset();
        Log().info("Loaded {} symbol records", symbol_index_.size());

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

        if (const auto entry_offset = img->virtual_address_to_file_offset(img->entry_point())) {
            hex_panel_.navigate_to_range(static_cast<std::size_t>(*entry_offset), 1);
            last_navigation_selection_ = current_selection_;
        }

        // PE keeps its entry-point disassembly via the legacy PeModel. ELF
        // entry-point disassembly via the unified image is future work (P4);
        // for now, click a byte in the Hex view to disassemble at that offset.
        if (const PeModel* pe = model_.pe()) {
            pe_model_ = *pe;
            disassemble_entry_point(4096);
        } else if (const auto entry_offset = img->virtual_address_to_file_offset(img->entry_point())) {
            disassemble_at_offset(static_cast<std::size_t>(*entry_offset), img->entry_point());
        }

        if (show_call_graph_panel_) {
            load_call_graph_sample(CallGraphSample::LoadedImage);
        } else {
            call_graph_sample_ = CallGraphSample::LoadedImage;
            call_graph_status_ = "Loaded-image graph will render when Call Graph is opened.";
            if (call_graph_texture_) {
                vulkan_.destroy_texture(*call_graph_texture_);
                call_graph_texture_.reset();
            }
        }
    }


    void UiApp::apply_structure_selection_navigation() {
        if (current_selection_.kind == SelectionKind::None ||
            current_selection_.kind == SelectionKind::Group) {
            return;
        }
        if (last_navigation_selection_ &&
            same_selection(*last_navigation_selection_, current_selection_)) {
            return;
        }

        const peelf::IBinaryImage* img = model_.image();
        if (img == nullptr) {
            return;
        }

        std::optional<std::uint64_t> file_offset = current_selection_.file_offset;
        if (!file_offset && current_selection_.virtual_address) {
            file_offset = img->virtual_address_to_file_offset(*current_selection_.virtual_address);
        }

        if (!file_offset) {
            last_navigation_selection_ = current_selection_;
            return;
        }
        if (*file_offset > static_cast<std::uint64_t>(std::numeric_limits<std::size_t>::max()) ||
            current_selection_.size > static_cast<std::uint64_t>(std::numeric_limits<std::size_t>::max())) {
            Log().warn("Selection '{}' range is too large for this platform", current_selection_.label);
            last_navigation_selection_ = current_selection_;
            return;
        }

        const std::size_t offset = static_cast<std::size_t>(*file_offset);
        const std::size_t size = current_selection_.size != 0
            ? static_cast<std::size_t>(current_selection_.size)
            : std::size_t{1};
        hex_panel_.navigate_to_range(offset, size);

        if (current_selection_.preferred_view == PreferredView::Disassembly) {
            const std::uint64_t display_address = current_selection_.virtual_address
                ? *current_selection_.virtual_address
                : *file_offset;
            disassemble_at_offset(offset, display_address);
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

    void UiApp::disassemble_at_offset(std::size_t file_offset) {
        std::uint64_t display_address = file_offset;
        if (const peelf::IBinaryImage* img = model_.image()) {
            if (const auto va = img->file_offset_to_virtual_address(file_offset)) {
                display_address = *va;
            }
        }
        disassemble_at_offset(file_offset, display_address);
    }

    void UiApp::disassemble_at_offset(std::size_t file_offset, std::uint64_t display_address) {
        if (!file_loaded_ || !disasm_.is_initialized()) {
            return;
        }
        const auto& bytes = model_.bytes();
        if (file_offset >= bytes.size()) {
            return;
        }
        constexpr std::size_t kWindow = 256;
        const std::size_t avail = bytes.size() - file_offset;
        const std::size_t size = std::min(kWindow, avail);
        current_instructions_ = disasm_.disassemble(bytes.data() + file_offset, size, display_address);
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
