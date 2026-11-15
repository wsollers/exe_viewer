#include "ui_app.hpp"
#include "decompile/structured_decompiler.hpp"
#include <format>
#include <cstdio>
#include <algorithm>
#include <limits>
#ifdef _WIN32
#define NOMINMAX
#include <windows.h>
#endif

namespace viewer {
namespace {
[[nodiscard]] DecompiledUnit make_decompile_message(DecompileStatus status, std::string diagnostic) {
    DecompiledUnit unit;
    unit.status = status;
    unit.provider = "Decompiler";
    unit.diagnostic = std::move(diagnostic);
    return unit;
}
}
void UiApp::initialize_decompiler() {
#ifdef _WIN32
    wchar_t executable[32768]{}; GetModuleFileNameW(nullptr, executable, 32768);
    decompiler_directory_ = std::filesystem::path(executable).parent_path();
#else
    std::error_code ec;
    decompiler_directory_ = std::filesystem::canonical("/proc/self/exe", ec).parent_path();
#endif
    auto settings = discover_decompilers(decompiler_directory_);
    const auto path = decompiler_directory_ / "decompiler.ini";
    if (std::filesystem::exists(path)) {
        auto saved = read_decompiler_settings(path);
        if (saved) settings = *saved;
        else decompiler_settings_status_ = saved.error().message;
    } else if (settings.ghidra_home.empty()) {
        settings.provider = DecompilerProvider::StructuredPseudoC;
    }
    decompiler_provider_ = static_cast<int>(settings.provider);
    decompiler_timeout_ = settings.timeout_seconds;
    std::snprintf(ghidra_home_, sizeof(ghidra_home_), "%s", settings.ghidra_home.string().c_str());
    std::snprintf(decompiler_java_, sizeof(decompiler_java_), "%s", settings.java.string().c_str());
    std::snprintf(decompiler_python_, sizeof(decompiler_python_), "%s", settings.python.string().c_str());
    std::snprintf(decompiler_retdec_, sizeof(decompiler_retdec_), "%s", settings.retdec.string().c_str());
}
void UiApp::clear_decompiler_caches() {
    decompile_cache_.clear();
    clear_ghidra_workspace_cache(default_ghidra_cache_directory());
    decompiler_settings_status_ = "Cleared decompiler result & workspace caches.";
}

void UiApp::request_decompile(bool force_reanalyze) {
    show_decompiler_ = true;
    focus_decompiler_ = true;
    if (decompile_job_.valid()) return;
    if (!current_selection_.virtual_address) {
        decompiled_ = make_decompile_message(DecompileStatus::NoFunction, "Select a mapped function or executable address first");
        return;
    }

    const std::uint64_t selected_va = *current_selection_.virtual_address;
    const auto* image = model_.image();
    DecompileRequest request;
    request.binary_sha256 = model_.content_sha256();
    request.patch_revision = model_.edit_revision();
    request.symbol_revision =
        symbol_revision_ ^ (annotations_.revision() * 0x9E3779B97F4A7C15ULL) ^
        (model_.demangle_symbols() ? 0xD3A461E5ULL : 0ULL);
    request.force_reanalyze = force_reanalyze;
    selected_code_ranges_.clear();
    selected_code_address_.reset();

    DecompilerSettings settings{};
    settings.provider = static_cast<DecompilerProvider>(decompiler_provider_);
    settings.ghidra_home = ghidra_home_;
    settings.java = decompiler_java_;
    settings.python = decompiler_python_;
    settings.retdec = decompiler_retdec_;
    settings.timeout_seconds = decompiler_timeout_;

    if (image != nullptr) {
        auto root = containing_function(*image, symbol_index_, selected_va, navigation_graph_root(selected_va));
        if (!root) {
            if (const auto mapped = image->virtual_address_to_file_offset(selected_va)) {
                root = SymbolRecord{
                    .name = std::format("sub_{:X}", selected_va),
                    .virtual_address = selected_va,
                    .file_offset = *mapped,
                    .function = true,
                    .library = {},
                };
            }
        }
        if (!root || !root->virtual_address) {
            decompiled_ = make_decompile_message(DecompileStatus::NoFunction, "No function selected");
            return;
        }
        SymbolRecord root_for_extent = *root;
        root_for_extent.file_offset = image->virtual_address_to_file_offset(*root->virtual_address);
        const std::size_t analysis_size = model_.analysis_image_size();
        const auto extent = discover_function_extent(*image, symbol_index_, root_for_extent, analysis_size);
        if (!extent) {
            decompiled_ = make_decompile_message(DecompileStatus::NoFunction, "Selection is not executable");
            return;
        }
        request.address = extent->virtual_address;
        request.architecture = image->architecture();
        request.endianness = image->endianness();
        if (const auto full = discover_function_extent(
                *image, symbol_index_, root_for_extent, analysis_size, std::numeric_limits<std::uint64_t>::max());
            full && (full->source == FunctionExtentSource::Symbol || full->source == FunctionExtentSource::RuntimeMetadata)) {
            request.function_size = full->size;
        }
        for (auto symbol : symbol_index_.records()) {
            symbol.function = symbol_has_code(*image, symbol);
            bool annotated = false;
            if (symbol.virtual_address) {
                if (const auto* note = annotations_.find(*symbol.virtual_address); note && !note->name.empty()) {
                    symbol.name = note->name;
                    symbol.source = SymbolSource::DebugSymbol;
                    annotated = true;
                }
            }
            if (!annotated && model_.demangle_symbols() && !symbol.demangled_name.empty()) {
                symbol.name = symbol.demangled_name;
            }
            request.symbols.push_back(std::move(symbol));
        }
        request.types = debug_types_;
        decompiled_root_ = root;
        request.thumb = image->architecture() == peelf::Architecture::ARM && thumb_mode_;

        const DecompileCacheKey cache_key = make_decompile_cache_key(request, settings);
        if (force_reanalyze) {
            decompile_cache_.invalidate_function(cache_key.binary_sha256, cache_key.function_address);
        } else if (auto cached = decompile_cache_.get(cache_key)) {
            decompile_revision_ = model_.edit_revision();
            decompile_generation_ = file_generation_;
            decompiler_thumb_ = thumb_mode_;
            decompile_annotation_revision_ = annotations_.revision();
            decompile_symbol_revision_ = symbol_revision_;
            decompiled_ = std::move(*cached);
            return;
        }

        auto bytes = model_.read_virtual_bytes(extent->virtual_address, static_cast<std::size_t>(extent->size));
        if (!bytes) {
            decompiled_ = make_decompile_message(DecompileStatus::Failed, bytes.error().message);
            return;
        }
        const GraphByteReader va_reader = [this](std::uint64_t va, std::size_t len)
            -> std::vector<std::uint8_t> {
            auto res = model_.read_virtual_bytes(va, len);
            return res ? std::move(*res) : std::vector<std::uint8_t>{};
        };
        request.fallback_graph = build_function_cfg_call_graph(
            *bytes,
            extent->virtual_address,
            image->architecture(),
            image->endianness(),
            static_cast<std::size_t>(extent->file_offset),
            root->name,
            thumb_mode_,
            true,
            va_reader);
        const auto chosen_provider = static_cast<DecompilerProvider>(decompiler_provider_);
        if (chosen_provider != DecompilerProvider::AnnotatedCode &&
            chosen_provider != DecompilerProvider::StructuredPseudoC) {
            if (model_.is_live_process()) {
                const auto span = model_.analysis_image_bytes();
                request.image_bytes.assign(span.begin(), span.end());
            } else {
                auto snapshot = model_.read_effective_bytes(0, model_.bytes().size());
                if (!snapshot) {
                    decompiled_ = make_decompile_message(DecompileStatus::Failed, snapshot.error().message);
                    return;
                }
                request.image_bytes = std::move(*snapshot);
            }
        }
        pending_decompile_cache_key_ = cache_key;
    } else if (model_.is_live_process()) {
        // Anonymous / JIT executable memory region without a backing module header.
        auto bytes = model_.read_virtual_bytes(selected_va, 4096);
        if (!bytes || bytes->empty()) {
            decompiled_ = make_decompile_message(DecompileStatus::NoFunction, "Selected live address is not readable");
            return;
        }
        const std::string fn_name = std::format("live_sub_{:X}", selected_va);
        request.address = selected_va;
        request.architecture = model_.architecture();
        request.endianness = model_.endianness();
        request.thumb = request.architecture == peelf::Architecture::ARM && thumb_mode_;
        const auto recs = symbol_index_.records();
        request.symbols.assign(recs.begin(), recs.end());
        request.fallback_graph = build_function_cfg_call_graph(
            *bytes,
            selected_va,
            model_.architecture(),
            model_.endianness(),
            0,
            fn_name,
            thumb_mode_,
            true);
        request.image_bytes = std::move(*bytes);
        decompiled_root_ = SymbolRecord{
            .name = fn_name,
            .virtual_address = selected_va,
            .file_offset = model_.virtual_address_to_offset(selected_va),
            .function = true,
            .library = {},
        };
        const DecompileCacheKey cache_key = make_decompile_cache_key(request, settings);
        if (force_reanalyze) {
            decompile_cache_.invalidate_function(cache_key.binary_sha256, cache_key.function_address);
        } else if (auto cached = decompile_cache_.get(cache_key)) {
            decompile_revision_ = model_.edit_revision();
            decompile_generation_ = file_generation_;
            decompiler_thumb_ = thumb_mode_;
            decompile_annotation_revision_ = annotations_.revision();
            decompile_symbol_revision_ = symbol_revision_;
            decompiled_ = std::move(*cached);
            return;
        }
        pending_decompile_cache_key_ = cache_key;
    } else {
        decompiled_ = make_decompile_message(DecompileStatus::NoFunction, "Select a mapped function first");
        return;
    }

    const auto resources = decompiler_directory_ / "resources";
    decompile_stop_ = {}; const auto token = decompile_stop_.get_token();
    decompile_revision_ = model_.edit_revision(); decompile_generation_ = file_generation_;
    decompiler_thumb_ = thumb_mode_;
    decompile_annotation_revision_ = annotations_.revision(); decompile_symbol_revision_ = symbol_revision_;
    decompiled_ = make_decompile_message(DecompileStatus::Ready, "Analyzing selected function...");
    decompile_job_ = std::async(std::launch::async, [request = std::move(request), settings, resources, token]() {
        BackendRunner runner;
        switch (settings.provider) {
        case DecompilerProvider::Ghidra: {
            auto unit = GhidraDecompiler(settings, resources, runner).decompile(request, token);
            if (unit.status == DecompileStatus::Unavailable && settings.ghidra_home.empty()) {
                auto fallback = StructuredPseudoCDecompiler{}.decompile(request, token);
                if (fallback.status == DecompileStatus::Ready) {
                    fallback.diagnostic = "Ghidra is not configured; decompiled with built-in Structured Pseudo-C.";
                    return fallback;
                }
            }
            return unit;
        }
        case DecompilerProvider::BinaryNinja:
            return BinaryNinjaDecompiler(settings.python, resources / "bn_decompile.py", runner).decompile(request, token);
        case DecompilerProvider::StructuredPseudoC:
            return StructuredPseudoCDecompiler{}.decompile(request, token);
        case DecompilerProvider::RetDec:
            return RetDecDecompiler(settings.retdec, runner, settings.timeout_seconds).decompile(request, token);
        default:
            return AnnotatedCodeDecompiler{}.decompile(request, token);
        }
    });
}
void UiApp::render_decompiler() {
    if (focus_decompiler_) { ImGui::SetNextWindowFocus(); focus_decompiler_ = false; }
    if (!ImGui::Begin("Decompiler",&show_decompiler_)) { ImGui::End(); return; }
    ImGui::BeginDisabled(decompile_job_.valid());
    ImGui::SetNextItemWidth(-1);
    ImGui::Combo("##provider",
                 &decompiler_provider_,
                 "Ghidra\0Binary Ninja HLIL\0Annotated assembly\0Structured Pseudo-C (built-in)\0RetDec CLI\0");
    if (ImGui::CollapsingHeader("Backend settings")) {
        if (decompiler_provider_ == 0) {
            ImGui::TextUnformatted("Ghidra installation folder"); ImGui::SetNextItemWidth(-1);
            ImGui::InputText("##ghidra", ghidra_home_, sizeof(ghidra_home_));
            ImGui::TextUnformatted("Java executable (JDK 25 for Ghidra 12.2)"); ImGui::SetNextItemWidth(-1);
            ImGui::InputText("##java", decompiler_java_, sizeof(decompiler_java_));
            ImGui::InputInt("Timeout (seconds)", &decompiler_timeout_);
        } else if (decompiler_provider_ == 1) {
            ImGui::TextWrapped("Headless API requires Binary Ninja Commercial or above. Personal is not supported by this adapter.");
            ImGui::SetNextItemWidth(-1); ImGui::InputTextWithHint("##python", "Python with Binary Ninja API",decompiler_python_,sizeof(decompiler_python_));
        } else if (decompiler_provider_ == 4) {
            ImGui::TextUnformatted("RetDec CLI executable");
            ImGui::SetNextItemWidth(-1);
            ImGui::InputTextWithHint("##retdec", "retdec-decompiler", decompiler_retdec_, sizeof(decompiler_retdec_));
            ImGui::InputInt("Timeout (seconds)", &decompiler_timeout_);
        }
        if (ImGui::Button("Save settings")) {
            DecompilerSettings settings{};
            settings.provider = static_cast<DecompilerProvider>(decompiler_provider_);
            settings.ghidra_home = ghidra_home_;
            settings.java = decompiler_java_;
            settings.python = decompiler_python_;
            settings.retdec = decompiler_retdec_;
            settings.timeout_seconds = decompiler_timeout_;
            if (decompiler_timeout_ < 10 || decompiler_timeout_ > 3600) decompiler_settings_status_ = "Timeout must be 10 to 3600 seconds.";
            else {
                const auto result = save_decompiler_settings(decompiler_directory_/"decompiler.ini", settings);
                decompiler_settings_status_ = result ? "Settings saved." : result.error().message;
            }
        }
        ImGui::TextWrapped("%s", decompiler_settings_status_.c_str());
    }
    ImGui::EndDisabled();
    ImGui::BeginDisabled(decompile_job_.valid());
    if (ImGui::Button("Analyze selection (F5)")) request_decompile(false);
    ImGui::SameLine();
    if (ImGui::Button("Re-analyze")) request_decompile(true);
    ImGui::SameLine();
    if (ImGui::Button("Clear Cache")) clear_decompiler_caches();
    ImGui::SameLine();
    bool demangle_decompile = model_.demangle_symbols();
    if (ImGui::Checkbox("Demangle", &demangle_decompile)) {
        model_.set_demangle_symbols(demangle_decompile);
        ++symbol_revision_;
    }
    ImGui::EndDisabled();
    if (decompile_job_.valid()) { ImGui::SameLine(); if (ImGui::Button("Cancel")) decompile_stop_.request_stop(); }
    ImGui::TextWrapped("%s", decompiled_.provider.c_str());
    if (!decompile_job_.valid() && decompiled_.status == DecompileStatus::Ready && !decompiled_.lines.empty()) {
        ImGui::SameLine();
        const std::string_view source_label = to_string(decompiled_.cache_source);
        ImGui::TextDisabled("[%.*s]", static_cast<int>(source_label.size()), source_label.data());
    }
    ImGui::TextWrapped("%s", decompiled_.diagnostic.c_str());
    if (!decompile_job_.valid() && decompiled_.status != DecompileStatus::Ready && decompiler_provider_ != 3) {
        if (ImGui::Button("Decompile with Structured Pseudo-C")) {
            decompiler_provider_ = 3;
            request_decompile();
        }
    }
    const bool stale = decompile_revision_ != model_.edit_revision() || decompiler_thumb_ != thumb_mode_ ||
        decompile_annotation_revision_ != annotations_.revision() || decompile_symbol_revision_ != symbol_revision_;
    if (stale) ImGui::TextWrapped("Bytes or symbols changed. Analyze again to refresh this snapshot.");
    std::optional<std::size_t> navigate;
    if (code_font_) ImGui::PushFont(code_font_);
    if (ImGui::BeginTable("decompiled_lines",2,ImGuiTableFlags_ScrollY|ImGuiTableFlags_ScrollX|ImGuiTableFlags_RowBg|ImGuiTableFlags_BordersInnerV|ImGuiTableFlags_Resizable)) {
        ImGui::TableSetupColumn("Address",ImGuiTableColumnFlags_WidthFixed,ImGui::CalcTextSize("0000000000000000").x+16);
        ImGui::TableSetupColumn("Code",ImGuiTableColumnFlags_WidthFixed,ImGui::GetFontSize()*80);
        ImGui::TableSetupScrollFreeze(1,1); ImGui::TableHeadersRow();
        ImGuiListClipper clipper; clipper.Begin(static_cast<int>(decompiled_.lines.size()));
        while (clipper.Step()) for(int i=clipper.DisplayStart;i<clipper.DisplayEnd;++i) {
            const auto& line=decompiled_.lines[static_cast<std::size_t>(i)]; ImGui::PushID(i);
            ImGui::TableNextRow(); ImGui::TableSetColumnIndex(0);
            if (line.address) {
                const auto label=std::format("{:016X}",*line.address);
                bool selected=current_selection_.virtual_address==line.address;
                for (const auto& range : line.ranges) if (current_selection_.virtual_address && *current_selection_.virtual_address>=range.address &&
                    *current_selection_.virtual_address-range.address<range.size) selected=true;
                if (ImGui::Selectable(label.c_str(),selected,ImGuiSelectableFlags_SpanAllColumns) && !stale) navigate=static_cast<std::size_t>(i);
                if (ImGui::IsItemHovered()) {
                    if (const SourceLineMapping* src = model_.find_source_line(*line.address, 32)) {
                        ImGui::SetTooltip("Source: %s:%u", src->file_path.c_str(), src->line);
                    }
                }
            } else ImGui::TextDisabled("—");
            ImGui::TableSetColumnIndex(1); ImGui::TextUnformatted(line.text.c_str());
            ImGui::PopID();
        }
        ImGui::EndTable();
    }
    if (code_font_) ImGui::PopFont();
    ImGui::End();
    if (navigate) select_decompiled_line(*navigate);
}
void UiApp::select_decompiled_line(std::size_t index) {
    const auto& line = decompiled_.lines.at(index);
    if (!line.address || !model_.has_file()) return;
    current_selection_.graph_root = decompiled_root_;
    navigate_to_address(*line.address, model_.image() != nullptr ? PreferredView::Graph : PreferredView::Disassembly);
    if (current_selection_.virtual_address != line.address) return;
    current_selection_.graph_root = decompiled_root_;
    selected_code_ranges_ = line.ranges;
    if (selected_code_ranges_.empty()) {
        auto instruction = std::ranges::find(current_instructions_, *line.address, &Instruction::address);
        selected_code_ranges_.push_back({*line.address, instruction == current_instructions_.end() ? 1 : instruction->bytes.size()});
    }
    std::vector<ByteRange> bytes;
    const std::uint64_t total_view = model_.view_size();
    for (const auto& range : selected_code_ranges_) {
        const auto offset = model_.virtual_address_to_offset(range.address);
        if (!offset || !range.size || *offset >= total_view || range.size > total_view - *offset) continue;
        const auto last = model_.virtual_address_to_offset(range.address + range.size - 1);
        if (!last || *last != *offset + range.size - 1) continue;
        bytes.push_back({static_cast<std::size_t>(*offset), static_cast<std::size_t>(range.size)});
    }
    if (!bytes.empty()) {
        hex_panel_.navigate_to_ranges(bytes); hex_panel_.set_visible(true);
        current_selection_.size = bytes.front().size; last_navigation_selection_ = current_selection_;
    }
    selected_code_address_ = line.address;
    if (decompiled_root_ && (!active_graph_root_ || active_graph_root_->virtual_address != decompiled_root_->virtual_address)) {
        pending_call_graph_root_ = decompiled_root_; pending_call_graph_delay_frames_ = 0;
    }
}
void UiApp::render_data_types() {
    if (!ImGui::Begin("Data Structures",&show_data_types_)) { ImGui::End(); return; }
    ImGui::SetNextItemWidth(-1);
    ImGui::InputTextWithHint("##type_search","Search structures, members, types, or data symbols...",data_type_filter_,sizeof(data_type_filter_));
    if (ImGui::BeginTabBar("data_views")) {
        if (ImGui::BeginTabItem("Structures")) {
            if (ImGui::SmallButton("Open Structure View...")) {
                open_structure_view();
            }
            ImGui::SameLine();
            ImGui::TextDisabled("(Built-in PE/ELF/Win32/Linux runtime schemas + loaded debug types)");
            if (debug_types_.empty() && decompiled_.types.empty())
                ImGui::TextWrapped("No PDB/DWARF/Ghidra types loaded; built-in PE/ELF/runtime schemas remain available in Structure View.");
            auto draw=[&](const DataTypeRecord& type) {
                if (!type_matches(type,data_type_filter_)) return;
                ImGui::PushID(type.name.c_str());
                if (ImGui::SmallButton("Apply")) {
                    if (current_selection_.virtual_address) {
                        open_structure_view(type.name, *current_selection_.virtual_address, false);
                    } else if (current_selection_.file_offset) {
                        open_structure_view(type.name, *current_selection_.file_offset, true);
                    } else {
                        open_structure_view(type.name);
                    }
                }
                if (ImGui::IsItemHovered()) {
                    ImGui::SetTooltip("Apply %s at current selection in Structure View", type.name.c_str());
                }
                ImGui::SameLine();
                const auto label=std::format("{} {} ({} bytes)",type.is_union ? "union" : "struct",type.name,type.size);
                if (ImGui::TreeNodeEx("##type",ImGuiTreeNodeFlags_SpanAvailWidth,"%s",label.c_str())) {
                    if (ImGui::BeginTable("members",4,ImGuiTableFlags_RowBg|ImGuiTableFlags_BordersInnerV|ImGuiTableFlags_Resizable)) {
                        for (const auto* name : {"Offset","Size","Member","Type"}) ImGui::TableSetupColumn(name);
                        ImGui::TableHeadersRow();
                        for (const auto& member : type.members) {
                            ImGui::TableNextRow(); ImGui::TableSetColumnIndex(0); ImGui::Text("0x%llX",static_cast<unsigned long long>(member.offset));
                            ImGui::TableSetColumnIndex(1); ImGui::Text("%llu",static_cast<unsigned long long>(member.size));
                            ImGui::TableSetColumnIndex(2); ImGui::TextUnformatted(member.name.c_str());
                            ImGui::TableSetColumnIndex(3); ImGui::TextUnformatted(member.type.c_str());
                        }
                        ImGui::EndTable();
                    }
                    ImGui::TreePop();
                }
                ImGui::PopID();
            };
            for (const auto& type : debug_types_) draw(type);
            for (const auto& type : decompiled_.types)
                if (std::ranges::none_of(debug_types_,[&](const auto& known){return known.name==type.name;})) draw(type);
            ImGui::EndTabItem();
        }
        if (ImGui::BeginTabItem("Data symbols")) {
            if (model_.image() && ImGui::BeginTable("data_symbols",3,ImGuiTableFlags_RowBg|ImGuiTableFlags_Resizable|ImGuiTableFlags_ScrollY)) {
                ImGui::TableSetupColumn("Name"); ImGui::TableSetupColumn("Address"); ImGui::TableSetupColumn("Size"); ImGui::TableHeadersRow();
                for (const auto& symbol : symbol_index_.records()) {
                    if (!symbol.virtual_address || symbol_has_code(*model_.image(),symbol) || !symbol_name_matches(symbol.name,data_type_filter_)) continue;
                    ImGui::PushID(&symbol); ImGui::TableNextRow(); ImGui::TableSetColumnIndex(0);
                    if (ImGui::Selectable(symbol.name.c_str(),current_selection_.virtual_address==symbol.virtual_address,ImGuiSelectableFlags_SpanAllColumns)) {
                        navigate_to_address(*symbol.virtual_address,PreferredView::Hex);
                        if (symbol.file_offset && symbol.size) hex_panel_.navigate_to_range(*symbol.file_offset,symbol.size);
                    }
                    ImGui::TableSetColumnIndex(1); ImGui::Text("%016llX",static_cast<unsigned long long>(*symbol.virtual_address));
                    ImGui::TableSetColumnIndex(2); ImGui::Text("%llu",static_cast<unsigned long long>(symbol.size)); ImGui::PopID();
                }
                ImGui::EndTable();
            }
            ImGui::EndTabItem();
        }
        ImGui::EndTabBar();
    }
    ImGui::End();
}
}
